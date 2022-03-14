# Setup instructions

In order to provide you the notebook already with the solutions (but hidden)
we are trying notebook extensions. You can consult the
[installation manual](https://jupyter-contrib-nbextensions.readthedocs.io/en/latest/),
but basically the following is required.

## B117

No additional setup needed (use the virtual as you are used to).

## VSCode

Unfortunately, the extensions won't work there, i.e. the solutions are
immediately visible - **don't peek** ;-).


## Own machines

Once you set up the virtual and install the requirements (same as usual) you need
to enable the extensions:

```shell
jupyter contrib nbextension install --sys-prefix
jupyter nbextension enable contrib_nbextensions_help_item/main
jupyter nbextension enable hide_input/main
jupyter nbextension enable exercise/main
jupyter nbextension enable exercise2/main
jupyter nbextension enable collapsible_headings/main
jupyter nbextension enable init_cell/main
```
# Test `server_communication` API

From within the virtual environment run:

```shell
pip install pytest
pytest
python -m doctest -v server_communication.py
python -m doctest -v utils.py
```
