import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="Hermes",
    version="0.0.1",
    author="CDulouard",
    author_email="clement.dulouard@alvarios.com",
    description="Network tools for python.",
    long_description=long_description,
    url="https://github.com/Alvarios/Hermes",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
