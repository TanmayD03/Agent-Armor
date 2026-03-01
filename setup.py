from setuptools import setup, find_packages

setup(
    name="kvlr",
    version="1.0.0",
    description="Zero-Trust Middleware for Agentic Coding",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Tanmay Dikey",
    author_email="enceladus441@gmail.com",
    license="MIT",
    python_requires=">=3.9",
    packages=find_packages(exclude=["tests*", "vulnerability_museum*"]),
    install_requires=[
        "click>=8.1.7",
        "rich>=13.7.0",
        "requests>=2.31.0",
        "pydantic>=2.5.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "dev": ["pytest>=7.4.3", "pytest-cov>=4.1.0"],
    },
    entry_points={
        "console_scripts": [
            "kvlr=cli.armor:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
    ],
)
