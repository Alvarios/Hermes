import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="Hermes",
    version="0.0.4",
    author="CDulouard",
    author_email="clement.dulouard@alvarios.com",
    description="Network tools for python.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Alvarios/Hermes",
    packages=setuptools.find_packages(),
    install_requires=[
        'cmake',
        'cffi',
        'numpy',
        'opencv-python'
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)

# python setup.py egg_info --egg-base=./
