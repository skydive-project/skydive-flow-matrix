# Skydive flow matrix

Return a flow matrix using Skydive sockets informations.

## Install requirements

```
Install virtualenv
Install graphviz
```

## Install

```bash
git clone https://github.com/skydive-project/skydive-flow-matrix.git
cd skydive-flow-matrix
virtualenv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install .
```

## Usage

```
skydive-flow-matrix --analyzer <analyzer:8082> --username=admin --password=toto --ssl --insecure

skydive-flow-matrix --analyzer <analyzer:8082> --at=-10m --duration 60 --use-flows
```

## Blog

For a more detailed example and discussion of the flow matrix, see the [flow
matrix blog post](http://skydive.network/blog/flow-matrix.html).
