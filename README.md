# Crypto Finance Development Kit for Python (CFD-PYTHON)

## Dependencies

- Python(CPython) (3.6 or higher)
- C/C++ Compiler
  - can compile c++11
- CMake (3.14.3 or higher)

### Windows

download and install files.
- [Python](https://www.python.org/)
- [CMake](https://cmake.org/) (3.14.3 or higher)
- MSVC
  - [Visual Studio](https://visualstudio.microsoft.com/downloads/) (Verified version is 2017 or higher)
  - [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/) (2017 or higher)
  - (Using only) [msvc redistribution package](https://support.microsoft.com/help/2977003/the-latest-supported-visual-c-downloads)

### MacOS

- [Homebrew](https://brew.sh/)

```Shell
# xcode cli tools
xcode-select --install

# install dependencies using Homebrew
brew install cmake python
```

### Linux(Ubuntu)

```Shell
# install dependencies using APT package Manager
apt-get install -y build-essential cmake python3 python3-dev 
(Ubuntu 20.04 or higher) apt-get install -y python-is-python3
curl https://sh.rustup.rs -sSf | sh  (select is 1)
```

cmake version 3.14.2 or lower, download from website and install cmake.
(https://cmake.org/download/)

### pip install

First update pip:
```
python -m pip install -U --user pip
  or
python3 -m pip install -U --user pip
```

Then install the required packages:
```
pip install --user wheel pipenv
```

### setup pipenv

use pipenv (for developer):
```
pipenv install -d
```

---

## Build native library on local

use python:
```
python setup.py build
  or
(ubuntu 18.04) python3 setup.py build
```

use pipenv:
```
pipenv run build
  or
(ubuntu 18.04) pipenv run build3
```

---

## install / uninstall

### from GitHub

```
pip install --user git+https://github.com/cryptogarageinc/cfd-python@master
```

### from sdist (source code)

Using unpack source code:
```Shell
pip install --user .
```

### from wheel

1. get releases asset. (ex. https://github.com/cryptogarageinc/cfd-python/releases/download/v0.0.1/cfd-0.0.1-cp38-cp38-win_amd64.whl )
2. install pip
```
pip install --user cfd-0.0.1-cp38-cp38-win_amd64.whl
```

---

## Test

### Test

use python:
```
python -m unittest discover -v tests
  or
(ubuntu 18.04) python3 -m unittest discover -v tests
```

use pipenv:
```
pipenv run test
  or
(ubuntu 18.04) pipenv run test3
```

---

## Information for developers

### using library

- cfd
  - cfd-core
    - [libwally-core](https://github.com/cryptogarageinc/libwally-core/tree/cfd-develop) (forked from [ElementsProject/libwally-core](https://github.com/ElementsProject/libwally-core))
    - [univalue](https://github.com/jgarzik/univalue) (for JSON encoding and decoding)

### formatter

- autopep8
  use pipenv:
  ```
  pipenv run format
  ```

### linter

- flake8
  use pipenv:
  ```
  pipenv run lint
  ```

### document tool

- doxygen

### support compilers

- Visual Studio (2017 or higher)
- Clang (7.x or higher)
- GCC (5.x or higher)

---

## Note

### Git connection:

Git repository connections default to HTTPS.
However, depending on the connection settings of GitHub, you may only be able to connect via SSH.
As a countermeasure, forcibly establish SSH connection by setting `CFD_CMAKE_GIT_SSH=1` in the environment variable.

- Windows: (On the command line. Or set from the system setting screen.)
```
set CFD_CMAKE_GIT_SSH=1
```

- MacOS & Linux(Ubuntu):
```
export CFD_CMAKE_GIT_SSH=1
```

### Ignore git update for CMake External Project:

Depending on your git environment, you may get the following error when checking out external:
```
  Performing update step for 'libwally-core-download'
  Current branch cmake_build is up to date.
  No stash entries found.
  No stash entries found.
  No stash entries found.
  CMake Error at /workspace/cfd-core/build/external/libwally-core/download/libwally-core-download-prefix/tmp/libwally-core-download-gitupdate.cmake:133 (message):


    Failed to unstash changes in:
    '/workspace/cfd-core/external/libwally-core/'.

    You will have to resolve the conflicts manually
```

This phenomenon is due to the `git update` related command.
Please set an environment variable that skips update processing.

- Windows: (On the command line. Or set from the system setting screen.)
```
set CFD_CMAKE_GIT_SKIP_UPDATE=1
```

- MacOS & Linux(Ubuntu):
```
export CFD_CMAKE_GIT_SKIP_UPDATE=1
```











# cfd-python
(WIP)


## install pipenv
pip install pipenv

## install from Pipfile
pipenv install --dev

## 
pipenv install --dev autopep8 flake8

## cleanup
pipenv run cleanup

## packaging wheel file

pip wheel
packaging: python ./setup.py bdist_wheel


If it does not work properly, discard the wheel on the python2 side and set PYTHONPATH.
```
export PYTHONPATH=$PYTHONPATH:~/.local/lib/python3.6/site-packages/wheel
```

```
On linux you need to be aware of PYTHONPATH.
```

### linked issue
- https://github.com/pypa/packaging-problems/issues/258


## packaging sdist file
packaging: python ./setup.py sdist

## install/uninstall
install:
python setup.py install --user
python setup.py install

new install:
pip install --user .

wheel install:
pip install (whl file)

git direct install:
pip install (git url)

uninstall:
pip uninstall cfd

### attention

Do not run setup.py install related commands in pipenv scripts.
If you run install with the pipenv script, it will be installed under virtual-env.
