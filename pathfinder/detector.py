import os
import json
import sys
import z3
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import (
    LowLevelCall, HighLevelCall, Binary, BinaryType, Assignment,
    SolidityCall, Unary, UnaryType,
)
from slither.core.variables.state_variable import StateVariable


class PathFinderDetector(AbstractDetector):
    ARGUMENT = "pathfinder"
    HELP = "Path-feasibility-aware reentrancy detection"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/yourname/slither-pathfinder"
    WIKI_TITLE = "PathFinder Reentrancy Detector"
    WIKI_DESCRIPTION = "Detects single- and cross-contract reentrancy with Z3 path feasibility."
    WIKI_EXPLOIT_SCENARIO = "Attacker reenters a function before its state is updated."
    WIKI_RECOMMENDATION = "Apply checks-effects-interactions or a reentrancy guard."

    COMPARISON_OPS = {
        BinaryType.GREATER: lambda a, b: a > b,
        BinaryType.GREATER_EQUAL: lambda a, b: a >= b,
        BinaryType.LESS: lambda a, b: a < b,
        BinaryType.LESS_EQUAL: lambda a, b: a <= b,
        BinaryType.EQUAL: lambda a, b: a == b,
    }

    MUTEX_MODIFIER_NAMES = {"nonreentrant", "reentrancyguard", "lock", "mutex"}
    AUTH_MODIFIER_NAMES = {
        "onlyowner", "onlyadmin", "onlyrole", "onlyminter",
        "auth", "requiresauth", "restricted", "onlyauthorized",
    }
    INIT_MODIFIER_NAMES = {"initializer", "onlyinitializing", "reinitializer"}

    def _detect(self):
        # Read configuration from environment variables (no PATHFINDER_ prefix)
        self.use_z3 = os.getenv("Z3", "1") == "1"
        self.use_mutex = os.getenv("PPT_MUTEX", "1") == "1"
        self.use_auth = os.getenv("PPT_AUTH", "1") == "1"
        self.use_init = os.getenv("PPT_INIT", "1") == "1"
        self.use_cei = os.getenv("PPT_CEI", "1") == "1"
        self.use_inherit = os.getenv("PPT_INHERIT", "1") == "1"
        self.use_xcfg = os.getenv("XCFG", "1") == "1"
        self.z3_timeout_ms = int(os.getenv("Z3_TIMEOUT_MS", "5000"))

        # DEBUG: verify env vars
        import sys
        print(f"DEBUG DETECTOR: Z3={os.getenv('Z3')}, MUTEX={os.getenv('PPT_MUTEX')}, AUTH={os.getenv('PPT_AUTH')}, INIT={os.getenv('PPT_INIT')}, CEI={os.getenv('PPT_CEI')}, INHERIT={os.getenv('PPT_INHERIT')}, XCFG={os.getenv('XCFG')}, TIMEOUT={os.getenv('Z3_TIMEOUT_MS')}", file=sys.stderr)

        results = []
        # Precompute call graph once
        self._call_graph, self._unknown_calls = self._build_call_graph()

        for contract in self.compilation_unit.contracts:
            for function in contract.functions_entry_points:
                if not function.is_implemented or function.is_constructor:
                    continue
                findings = self._analyze_function(function)
                results.extend(findings)
        return results

    # ======================================================================
    # Call graph (Step 4)
    # ======================================================================

    def _build_call_graph(self):
        """
        Returns:
          graph: dict[(contract_name, func_name)] -> list of
                 ((target_contract_name, target_func_name), call_kind)
                 where call_kind in {"named", "receive", "fallback"}
          unknown: list of (contract_name, func_name, reason)
        """
        graph = {}
        unknown = []

        # Map from contract name to contract object for lookup
        contracts_by_name = {c.name: c for c in self.compilation_unit.contracts}

        for contract in self.compilation_unit.contracts:
            for func in contract.functions:
                if not func.is_implemented:
                    continue
                key = (contract.name, func.name)
                edges = []

                for node in func.nodes:
                    for ir in node.all_slithir_operations():
                        if not isinstance(ir, (LowLevelCall, HighLevelCall)):
                            continue
                        target, kind, reason = self._resolve_external_call(
                            ir, contracts_by_name
                        )
                        if target is not None:
                            edges.append((target, kind))
                        else:
                            unknown.append((contract.name, func.name, reason))

                if edges:
                    graph[key] = edges

        return graph, unknown

    def _resolve_external_call(self, ir, contracts_by_name):
        """
        Resolve a LowLevelCall/HighLevelCall to a target (contract, function)
        if it lives in the same compilation unit.

        Returns (target, kind, reason) where target is
        (contract_name, function_name) or None, and kind is
        "named" / "receive" / "fallback".
        """
        # Try to get the called function object from SlithIR
        called = getattr(ir, "function", None)
        if called is not None:
            try:
                contract = called.contract
                if contract is not None and contract.name in contracts_by_name:
                    return (contract.name, called.name), "named", None
            except Exception:
                pass

        # Try to get destination contract via the IR's destination variable
        dest = getattr(ir, "destination", None) or getattr(ir, "dest", None)
        if dest is not None:
            # If destination is a StateVariable of type Contract, resolve
            dest_type = getattr(dest, "type", None)
            if dest_type is not None:
                target_contract = getattr(dest_type, "type", None)
                if target_contract is not None:
                    name = getattr(target_contract, "name", None)
                    if name in contracts_by_name:
                        # Low-level call to known contract: try receive/fallback
                        target_obj = contracts_by_name[name]
                        if name in [c.name for c in self.compilation_unit.contracts]:
                            for fn_name in ("receive", "fallback"):
                                fn = next(
                                    (f for f in target_obj.functions
                                     if f.name == fn_name and f.is_implemented),
                                    None,
                                )
                                if fn is not None:
                                    return (name, fn.name), fn_name, None

        # Could not resolve to a known contract in the compilation unit
        return None, None, "unknown-external"

    # ======================================================================
    # Single-function analysis (Steps 2 + 3, unchanged)
    # ======================================================================

    def _analyze_function(self, function):
        findings = []
        nodes = list(function.nodes)
        contract_name = function.contract.name if function.contract else "?"
        file_path = function.contract.source_mapping.filename.absolute if function.contract and function.contract.source_mapping else "?"

        for i, node in enumerate(nodes):
            if not any(isinstance(ir, (LowLevelCall, HighLevelCall))
                       for ir in node.all_slithir_operations()):
                continue

            for later_node in nodes[i + 1:]:
                if not later_node.state_variables_written:
                    continue

                # --- Step 3 protections on the entry function ---
                if self._has_mutex_protection(function, node):
                    continue
                if self._has_auth_protection(function, node):
                    continue
                if self._has_init_protection(function, node):
                    continue
                if self._has_cei_protection(function, node, later_node):
                    continue

                # --- Single-contract Z3 (Step 2) ---
                if self.use_z3:
                    path_constraints = self._collect_path_conditions(function, node)
                    z3_result = self._check_z3(path_constraints)

                    # Emit structured JSON for evaluation
                    finding_record = {
                        "file": str(file_path),
                        "contract": contract_name,
                        "function": function.name,
                        "config": "single-contract",
                        "z3_result": z3_result,
                        "sat_finding": z3_result == "SAT",
                        "unknown_finding": z3_result == "UNKNOWN",
                        "detail": f"external call in {function.name} followed by state write in {later_node}"
                    }
                    print(f"PATHFINDER_JSON:{json.dumps(finding_record)}", file=sys.stderr)

                    if z3_result == "SAT":
                        info = [
                            f"Reentrancy (single-contract, Path Feasible): "
                            f"external call in {function.name} followed by "
                            f"state write in {later_node}.\\n"
                        ]
                        findings.append(self.generate_result(info, node))
                        # Still attempt cross-contract analysis as well
                        if self.use_xcfg:
                            findings.extend(
                                self._cross_contract_analysis(function, node, later_node)
                            )
                    # UNKNOWN and UNSAT produce no finding (abstain / negative)
                else:
                    # Z3 disabled: report as potential reentrancy (conservative)
                    info = [
                        f"Reentrancy (single-contract, Z3 disabled): "
                        f"external call in {function.name} followed by "
                        f"state write in {later_node}.\\n"
                    ]
                    findings.append(self.generate_result(info, node))
                    if self.use_xcfg:
                        findings.extend(
                            self._cross_contract_analysis(function, node, later_node)
                        )

                # NOTE: removed 'break' to analyze all call sites in the function

        return findings

    # ======================================================================
    # Cross-contract analysis (Step 4)
    # ======================================================================

    def _cross_contract_analysis(self, function, call_node, later_node):
        """
        For an external call node that was not suppressed, check whether the
        call target is a known contract in the compilation unit and whether
        the target has a callback entry that writes sensitive state.

        Returns a list of findings (0 or 1 typically).
        """
        contract = function.contract
        key = (contract.name, function.name)
        edges = self._call_graph.get(key, [])
        if not edges:
            return []

        findings = []
        file_path = contract.source_mapping.filename_absolute if contract else "?"
        for (target_contract_name, target_fn_name), kind in edges:
            target_contract = next(
                (c for c in self.compilation_unit.contracts
                 if c.name == target_contract_name),
                None,
            )
            if target_contract is None:
                continue

            target_fn = next(
                (f for f in target_contract.functions
                 if f.name == target_fn_name and f.is_implemented),
                None,
            )
            if target_fn is None:
                continue

            # Look for a state write in the target callback
            target_write_node = None
            for t_node in target_fn.nodes:
                if t_node.state_variables_written:
                    target_write_node = t_node
                    break

            if target_write_node is None:
                continue

            # Combine caller and target path constraints
            caller_constraints = self._collect_path_conditions(function, call_node)
            target_constraints = self._collect_path_conditions(target_fn, target_write_node)
            all_constraints = caller_constraints + target_constraints

            z3_result = self._check_z3(all_constraints)

            # Emit structured JSON for evaluation
            finding_record = {
                "file": str(file_path),
                "contract": contract.name,
                "function": function.name,
                "config": "cross-contract",
                "z3_result": z3_result,
                "sat_finding": z3_result == "SAT",
                "unknown_finding": z3_result == "UNKNOWN",
                "detail": f"{contract.name}.{function.name} external call -> {target_contract_name}.{target_fn_name} ({kind}) writes {target_write_node}"
            }
            print(f"PATHFINDER_JSON:{json.dumps(finding_record)}", file=sys.stderr)

            if z3_result == "SAT":
                info = [
                    f"Reentrancy (cross-contract, Path Feasible): "
                    f"{contract.name}.{function.name} external call -> "
                    f"{target_contract_name}.{target_fn_name} ({kind}) "
                    f"writes {target_write_node}.\\n"
                ]
                findings.append(self.generate_result(info, call_node))
            # UNKNOWN and UNSAT produce no finding (abstain / negative)

        return findings

    # ======================================================================
    # Step 3 protections (unchanged from previous version)
    # ======================================================================

    def _has_mutex_protection(self, function, call_node):
        if not self.use_mutex:
            return False
        for mod in function.modifiers:
            if mod.name.lower() in self.MUTEX_MODIFIER_NAMES:
                return True
        if self._find_manual_lock(function, call_node) is not None:
            return True
        if self._modifier_body_has_guard(function):
            return True
        return False

    def _find_manual_lock(self, function, call_node):
        nodes = list(function.nodes)
        call_idx = next((idx for idx, n in enumerate(nodes) if n == call_node), None)
        if call_idx is None:
            return None

        true_set_before = set()
        for n in nodes[:call_idx]:
            for ir in n.all_slithir_operations():
                if isinstance(ir, Assignment):
                    lval, rval = ir.lvalue, ir.rvalue
                    if hasattr(lval, "name") and self._is_bool_const(rval, True):
                        true_set_before.add(lval.name)
        false_set_after = set()
        for n in nodes[call_idx + 1:]:
            for ir in n.all_slithir_operations():
                if isinstance(ir, Assignment):
                    lval, rval = ir.lvalue, ir.rvalue
                    if hasattr(lval, "name") and self._is_bool_const(rval, False):
                        false_set_after.add(lval.name)
        common = true_set_before & false_set_after
        return next(iter(common)) if common else None

    def _modifier_body_has_guard(self, function, depth=0):
        if depth > 3:
            return False
        for mod in function.modifiers:
            if mod.name.lower() in self.MUTEX_MODIFIER_NAMES:
                continue
            mod_lock = self._modifier_defines_lock(mod)
            if mod_lock:
                return True
            if self._modifier_has_nested_guard(mod, depth + 1):
                return True
        return False

    def _modifier_defines_lock(self, mod):
        true_vars = set()
        false_vars = set()
        for n in mod.nodes:
            for ir in n.all_slithir_operations():
                if isinstance(ir, Assignment):
                    lval, rval = ir.lvalue, ir.rvalue
                    name = getattr(lval, "name", None)
                    if not name:
                        continue
                    if self._is_bool_const(rval, True):
                        true_vars.add(name)
                    elif self._is_bool_const(rval, False):
                        false_vars.add(name)
        common = true_vars & false_vars
        return next(iter(common)) if common else None

    def _modifier_has_nested_guard(self, mod, depth):
        if depth > 3:
            return False
        for n in mod.nodes:
            for ir in n.all_slithir_operations():
                mod_call = getattr(ir, "modifier", None)
                if mod_call is None:
                    continue
                inner_name = getattr(mod_call, "name", "").lower()
                if inner_name in self.MUTEX_MODIFIER_NAMES:
                    return True
                if self._modifier_defines_lock(mod_call):
                    return True
        return False

    def _has_auth_protection(self, function, call_node):
        if not self.use_auth:
            return False
        for mod in function.modifiers:
            if mod.name.lower() in self.AUTH_MODIFIER_NAMES:
                return True
            if self._modifier_body_checks_msg_sender(mod):
                return True
        nodes = list(function.nodes)
        call_idx = next((idx for idx, n in enumerate(nodes) if n == call_node), None)
        if call_idx is None:
            return False
        for n in nodes[:call_idx]:
            for ir in n.all_slithir_operations():
                if isinstance(ir, Binary) and ir.type in self.COMPARISON_OPS:
                    if (self._mentions_msg_sender(ir.variable_left)
                            or self._mentions_msg_sender(ir.variable_right)):
                        return True
                if isinstance(ir, SolidityCall) and "require" in ir.function.name:
                    for arg in ir.arguments:
                        if self._mentions_msg_sender(arg):
                            return True
        return False

    def _modifier_body_checks_msg_sender(self, mod):
        for n in mod.nodes:
            for ir in n.all_slithir_operations():
                if isinstance(ir, Binary) and ir.type in self.COMPARISON_OPS:
                    if (self._mentions_msg_sender(ir.variable_left)
                            or self._mentions_msg_sender(ir.variable_right)):
                        return True
                if isinstance(ir, SolidityCall) and "require" in ir.function.name:
                    for arg in ir.arguments:
                        if self._mentions_msg_sender(arg):
                            return True
        return False

    def _has_init_protection(self, function, call_node):
        if not self.use_init:
            return False
        for mod in function.modifiers:
            if mod.name.lower() in self.INIT_MODIFIER_NAMES:
                return True
        nodes = list(function.nodes)
        call_idx = next((idx for idx, n in enumerate(nodes) if n == call_node), None)
        if call_idx is None:
            return False
        init_vars = set()
        for n in nodes[:call_idx]:
            for ir in n.all_slithir_operations():
                if isinstance(ir, Assignment):
                    lval, rval = ir.lvalue, ir.rvalue
                    if (isinstance(lval, StateVariable)
                            and self._is_bool_const(rval, True)):
                        init_vars.add(lval.name)
        if not init_vars:
            return False
        for n in nodes[:call_idx]:
            for ir in n.all_slithir_operations():
                if isinstance(ir, Unary) and ir.type == UnaryType.BANG:
                    if getattr(ir.rvalue, "name", None) in init_vars:
                        return True
                if isinstance(ir, Binary) and ir.type in self.COMPARISON_OPS:
                    for operand in (ir.variable_left, ir.variable_right):
                        if getattr(operand, "name", None) in init_vars:
                            return True
                if isinstance(ir, SolidityCall) and "require" in ir.function.name:
                    for arg in ir.arguments:
                        if getattr(arg, "name", None) in init_vars:
                            return True
        return False

    def _has_cei_protection(self, function, call_node, write_node):
        if not self.use_cei:
            return False
        written_names = set()
        for ir in write_node.all_slithir_operations():
            lval = getattr(ir, "lvalue", None)
            if lval is None:
                continue
            resolved = self._resolve_var_name(lval)
            if resolved:
                written_names.add(resolved)
        if not written_names:
            return False
        nodes = list(function.nodes)
        call_idx = next((idx for idx, n in enumerate(nodes) if n == call_node), None)
        if call_idx is None:
            return False
        # True CEI: the SAME state variable is WRITTEN (assigned) before the external call.
        # A mere comparison (require, >=, ==) is a guard, not CEI.
        for n in nodes[:call_idx]:
            for ir in n.all_slithir_operations():
                if isinstance(ir, Assignment):
                    lname = self._resolve_var_name(ir.lvalue)
                    if lname in written_names:
                        # Check if it's a meaningful state update (not just zeroing)
                        # Zeroing before call IS CEI (e.g., balances[msg.sender] = 0)
                        return True
        return False

    def _resolve_var_name(self, operand):
        if operand is None:
            return None
        if isinstance(operand, StateVariable):
            return operand.name
        points_to = getattr(operand, "points_to", None)
        if points_to is not None:
            return self._find_state_var_in_expr(points_to)
        return getattr(operand, "name", None)

    def _find_state_var_in_expr(self, expr):
        seen = set()

        def walk(e):
            if e is None or id(e) in seen:
                return None
            seen.add(id(e))
            if isinstance(e, StateVariable):
                return e.name
            for attr in ("variable_left", "variable_right", "expression",
                         "variable"):
                child = getattr(e, attr, None)
                if child is not None:
                    r = walk(child)
                    if r:
                        return r
            return None
        return walk(expr)

    @staticmethod
    def _is_zero_const(operand):
        raw = getattr(operand, "value", None)
        if raw is None:
            return False
        try:
            return int(raw) == 0
        except (ValueError, TypeError):
            return False

    # ======================================================================
    # Shared helpers
    # ======================================================================

    def _mentions_msg_sender(self, expr):
        seen = set()

        def walk(e):
            if e is None or id(e) in seen:
                return False
            seen.add(id(e))
            if getattr(e, "name", None) == "msg.sender":
                return True
            for attr in ("variable_left", "variable_right", "expression"):
                child = getattr(e, attr, None)
                if child is not None and walk(child):
                    return True
            return False
        return walk(expr)

    @staticmethod
    def _is_bool_const(operand, value):
        raw = getattr(operand, "value", None)
        if raw is None:
            return False
        try:
            return bool(int(raw)) == value
        except (ValueError, TypeError):
            return raw is value

    def _collect_path_conditions(self, function, call_node=None):
        """
        Collect path conditions that dominate the external call.
        If call_node is None, returns empty list (conservative: no constraints = SAT).
        Uses CFG dominance: only constraints from nodes that dominate the call_node
        are on all paths to the call, so they are guaranteed to be checked.
        """
        constraints = []

        if call_node is None:
            return constraints

        # Get nodes that dominate the call_node (on ALL paths to the call)
        try:
            dominators = call_node.dominators
        except AttributeError:
            return constraints

        # Include the call_node itself (in case it has require/if)
        dominating_nodes = set(dominators)
        dominating_nodes.add(call_node)

        for node in function.nodes:
            if node not in dominating_nodes:
                continue
            for ir in node.all_slithir_operations():
                # Collect require() calls
                if isinstance(ir, SolidityCall) and "require" in ir.function.name:
                    for arg in ir.arguments:
                        z3_expr = self._expr_to_z3(arg)
                        if z3_expr is not None:
                            constraints.append(z3_expr)
                # Collect if conditions (binary comparisons in conditionals)
                elif isinstance(ir, Binary) and ir.type in self.COMPARISON_OPS:
                    z3_expr = self._binary_to_z3(ir)
                    if z3_expr is not None:
                        constraints.append(z3_expr)

        return constraints

    def _binary_to_z3(self, binary):
        z3_op = self.COMPARISON_OPS.get(binary.type)
        if z3_op is None:
            return None
        left = self._operand_to_z3(binary.variable_left)
        right = self._operand_to_z3(binary.variable_right)
        if left is None or right is None:
            return None
        return z3_op(left, right)

    def _expr_to_z3(self, expr):
        """Convert arbitrary SlithIR expression to Z3 constraint."""
        if expr is None:
            return None
        # Binary comparison
        if isinstance(expr, Binary) and expr.type in self.COMPARISON_OPS:
            return self._binary_to_z3(expr)
        # Boolean variable (e.g., a flag)
        if hasattr(expr, "type") and "bool" in str(expr.type).lower():
            name = getattr(expr, "name", None)
            if name:
                return z3.Bool(name)
        # Try as operand
        return self._operand_to_z3(expr)

    def _operand_to_z3(self, operand):
        if operand is None:
            return None
        # Literal value
        if hasattr(operand, "value") and not hasattr(operand, "name"):
            try:
                val = operand.value
                # Boolean literal
                if isinstance(val, str) and val.lower() in ("true", "false"):
                    return z3.BoolVal(val.lower() == "true")
                # Integer literal
                return z3.IntVal(int(val))
            except (ValueError, TypeError):
                return None
        name = getattr(operand, "name", None)
        if not name:
            return None
        # Type-aware variable encoding
        # Booleans
        if hasattr(operand, "type") and "bool" in str(operand.type).lower():
            return z3.Bool(name)
        # Addresses (160-bit)
        if hasattr(operand, "type") and "address" in str(operand.type).lower():
            return z3.BitVec(name, 160)
        # Default: integer
        return z3.Int(name)

    def _check_z3(self, constraints):
        s = z3.Solver()
        s.set("timeout", self.z3_timeout_ms)
        for c in constraints:
            s.add(c)
        result = s.check()
        if result == z3.sat:
            return "SAT"
        elif result == z3.unsat:
            return "UNSAT"
        return "UNKNOWN"