from setuptools import setup
import os

with open("requirements.txt", "r", encoding="utf-8") as f:
    install_requires = [
        line.strip() for line in f if line.strip() and not line.startswith("#")
    ]

setup(
    name="netcheck-cli",
    version="0.1.0",
    description="A high-performance, asynchronous digital identity validation and network endpoint auditing tool.",
    author="Dhruv Rathod",
    py_modules=["main"],
    package_data={"": ["config/*.json"]},
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "netcheckcli=main:cli",
            "netcheck=main:cli",
        ],
    },
    python_requires=">=3.8",
)
