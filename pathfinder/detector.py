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

        for i, node in enumerate(nodes):
            if not any(isinstance(ir, (LowLevelCall, HighLevelCall))
                       for ir in node.all_slithir_operations()):
                continue

            for later_node in nodes[i + 1:]:
                if not later_node.state_variables_written:
                    continue

                # --- Step 3 protections on the entry function ---
                if self._has_mutex_protection(function, node):
                    print(f"[DEBUG] {contract_name}.{function.name} "
                          f"suppressed by mutex protection")
                    break
                if self._has_auth_protection(function, node):
                    print(f"[DEBUG] {contract_name}.{function.name} "
                          f"suppressed by authorization protection")
                    break
                if self._has_init_protection(function, node):
                    print(f"[DEBUG] {contract_name}.{function.name} "
                          f"suppressed by initialization protection")
                    break
                if self._has_cei_protection(function, node, later_node):
                    print(f"[DEBUG] {contract_name}.{function.name} "
                          f"suppressed by CEI protection")
                    break

                # --- Single-contract Z3 (Step 2) ---
                path_constraints = self._collect_path_conditions(function)
                z3_result = self._check_z3(path_constraints)
                print(f"[DEBUG] {contract_name}.{function.name} "
                      f"single z3={z3_result}")

                if z3_result == "SAT":
                    info = [
                        f"Reentrancy (single-contract, Path Feasible): "
                        f"external call in {function.name} followed by "
                        f"state write in {later_node}.\n"
                    ]
                    findings.append(self.generate_result(info, node))
                    # Still attempt cross-contract analysis as well
                    findings.extend(
                        self._cross_contract_analysis(function, node, later_node)
                    )
                elif z3_result == "UNKNOWN":
                    info = [
                        f"Reentrancy (single-contract, Path UNKNOWN): "
                        f"external call in {function.name} followed by "
                        f"state write in {later_node}. Solver unknown.\n"
                    ]
                    findings.append(self.generate_result(info, node))

                break

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
                print(f"[DEBUG-CROSS] {contract.name}.{function.name} -> "
                      f"{target_contract_name}.{target_fn_name} : "
                      f"no sensitive write in target")
                continue

            # Combine caller and target path constraints
            caller_constraints = self._collect_path_conditions(function)
            target_constraints = self._collect_path_conditions(target_fn)
            all_constraints = caller_constraints + target_constraints

            z3_result = self._check_z3(all_constraints)
            print(f"[DEBUG-CROSS] {contract.name}.{function.name} -> "
                  f"{target_contract_name}.{target_fn_name} ({kind}) "
                  f"z3={z3_result}")

            if z3_result == "SAT":
                info = [
                    f"Reentrancy (cross-contract, Path Feasible): "
                    f"{contract.name}.{function.name} external call -> "
                    f"{target_contract_name}.{target_fn_name} ({kind}) "
                    f"writes {target_write_node}.\n"
                ]
                findings.append(self.generate_result(info, call_node))
            elif z3_result == "UNKNOWN":
                info = [
                    f"Reentrancy (cross-contract, Path UNKNOWN): "
                    f"{contract.name}.{function.name} -> "
                    f"{target_contract_name}.{target_fn_name} ({kind}). "
                    f"Solver unknown.\n"
                ]
                findings.append(self.generate_result(info, call_node))

        return findings

    # ======================================================================
    # Step 3 protections (unchanged from previous version)
    # ======================================================================

    def _has_mutex_protection(self, function, call_node):
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
                print(f"[DEBUG-INHERIT] {function.contract.name}.{function.name} "
                      f"modifier {mod.name} contains lock pattern ({mod_lock})")
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
        for mod in function.modifiers:
            if mod.name.lower() in self.AUTH_MODIFIER_NAMES:
                return True
            if self._modifier_body_checks_msg_sender(mod):
                print(f"[DEBUG-INHERIT] {function.contract.name}.{function.name} "
                      f"modifier {mod.name} checks msg.sender")
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
        print(f"[DEBUG-INIT] {function.contract.name}.{function.name} "
              f"init_vars={init_vars}")
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
        written_names = set()
        for ir in write_node.all_slithir_operations():
            lval = getattr(ir, "lvalue", None)
            if lval is None:
                continue
            resolved = self._resolve_var_name(lval)
            if resolved:
                written_names.add(resolved)
        print(f"[DEBUG-CEI] {function.contract.name}.{function.name} "
              f"written_names={written_names}")
        if not written_names:
            return False
        nodes = list(function.nodes)
        call_idx = next((idx for idx, n in enumerate(nodes) if n == call_node), None)
        if call_idx is None:
            return False
        for n in nodes[:call_idx]:
            for ir in n.all_slithir_operations():
                if isinstance(ir, Assignment):
                    lname = self._resolve_var_name(ir.lvalue)
                    if lname in written_names and self._is_zero_const(ir.rvalue):
                        print(f"[DEBUG-CEI] {function.contract.name}.{function.name} "
                              f"zeroed {lname} before call")
                        return True
        for n in nodes[:call_idx]:
            for ir in n.all_slithir_operations():
                if isinstance(ir, Binary) and ir.type in self.COMPARISON_OPS:
                    ln = self._resolve_var_name(ir.variable_left)
                    rn = self._resolve_var_name(ir.variable_right)
                    if ln in written_names or rn in written_names:
                        print(f"[DEBUG-CEI] {function.contract.name}.{function.name} "
                              f"checked {ln or rn} before call")
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

    def _collect_path_conditions(self, function):
        constraints = []
        for node in function.nodes:
            for ir in node.all_slithir_operations():
                if isinstance(ir, Binary) and ir.type in self.COMPARISON_OPS:
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

    def _operand_to_z3(self, operand):
        if operand is None:
            return None
        if hasattr(operand, "value") and not hasattr(operand, "name"):
            try:
                return z3.IntVal(int(operand.value))
            except (ValueError, TypeError):
                return None
        name = getattr(operand, "name", None)
        if not name:
            return None
        return z3.Int(name)

    def _check_z3(self, constraints):
        s = z3.Solver()
        s.set("timeout", 5000)
        for c in constraints:
            s.add(c)
        result = s.check()
        if result == z3.sat:
            return "SAT"
        elif result == z3.unsat:
            return "UNSAT"
        return "UNKNOWN"