import setuptools

with open("README.md", "r") as f_readme:
    long_description = f_readme.read()

setuptools.setup(
    name="fastcopy",
    version="0.1.4",
    python_requires=">=3.6",
    author="Seamile",
    author_email="lanhuermao@gmail.com",
    description="A multi-threaded file transfer tool over SSH. The goal is to replace SCP.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/seamile/FastCopy",
    packages=['fastcopy'],
    install_requires=[
        "paramiko>=2.7.2",
        "python-daemon>=2.3.0",
        "rich>=10.6.0"
    ],
    entry_points={
        'console_scripts': [
            'fcp=fastcopy.client:main',
            'fcpd=fastcopy.server:main'
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Topic :: Internet',
        'Topic :: Utilities',
    ],
)
