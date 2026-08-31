from setuptools import setup
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

readme_path = os.path.join(BASE_DIR, "README.md")
with open(readme_path, "r", encoding="utf-8") as f:
    long_description = f.read()

req_path = os.path.join(BASE_DIR, "requirements.txt")
if os.path.exists(req_path):
    with open(req_path, "r", encoding="utf-8") as f:
        install_requires = [
            line.strip() for line in f if line.strip() and not line.startswith("#")
        ]
else:
    install_requires = [
        "aiohttp==3.11.11",
        "python-dotenv==1.0.1",
        "colorama==0.4.6",
    ]

setup(
    name="netcheck-osint",
    version="0.1.1",
    description="A high-performance, asynchronous digital identity validation and network endpoint auditing tool.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Dhruv Rathod",
    py_modules=["main"],
    package_data={"": ["config/*.json"]},
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "netcheck=main:cli",
            "netcheckcli=main:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
)
