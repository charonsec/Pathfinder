from setuptools import setup, find_packages

setup(
    name="slither-pathfinder",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "slither-analyzer>=0.10.0",
        "z3-solver>=4.12.0",
        "celery>=5.3.0",
        "redis>=5.0.0",
        "pandas>=2.0.0",
        "solc-select>=1.0.0",
    ],
    entry_points={
    "slither_analyzer.plugin": "pathfinder = pathfinder:make_plugin",
    },
)