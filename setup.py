from setuptools import setup

from chamberenv._version import __version__


setup(
    name="chamberenv",
    version=__version__,
    description=("Manage chamber environments."),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Norman Moeschter-Schenck",
    author_email="norman.moeschter@gmail.com",
    url="https://github.com/normoes/chamberenv",
    download_url=f"https://github.com/normoes/chamberenv/archive/{__version__}.tar.gz",
    install_requires=["requests>=2.23.0"],
    packages=["chamberenv"],
    scripts=["bin/chamberenv"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python",
    ],
)
