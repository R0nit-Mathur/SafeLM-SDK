from setuptools import setup, find_packages

setup(
    name="safelm-sdk",
    version="1.0.0",
    description="SafeLM - The Ultimate Zero-Dependency Plug-and-Play Security SDK for LLMs",
    author="SafeLM Team",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
