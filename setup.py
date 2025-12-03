from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="iot-scan",
    version="1.0.0",
    author="Yasir N.",
    author_email="y451rmahar@gmail.com",
    description="A CLI tool to discover and scan IoT devices for security vulnerabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sudoyasir/iot-scan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "iot-scan=src.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json"],
    },
)
