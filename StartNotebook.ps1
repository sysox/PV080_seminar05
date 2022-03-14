# This is a PowerShell script that will open up Jupyter notebook using
# the single read-only virtual.
#
# This will only work in the room B117 on the faculty machines.
# Do not run this elsewhere.

# activate the virtual environment
I:\pv080\seminars\venv\Scripts\activate.ps1

jupyter contrib nbextension install --sys-prefix
jupyter nbextension enable contrib_nbextensions_help_item/main
jupyter nbextension enable hide_input/main
jupyter nbextension enable exercise/main
jupyter nbextension enable exercise2/main
jupyter nbextension enable collapsible_headings/main
jupyter nbextension enable init_cell/main

# start the notebook
jupyter notebook
