import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="Hermes",
    version="0.0.5",
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
        "cryptography",
        'numpy',
        'opencv-python'
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha"
    ],
    python_requires='>=3.6',
)

# python setup.py egg_info --egg-base=./
