# Artifact

To reproduce the GnuTLS state machines from the paper, run `./run_experiments.sh`.
This will leave 4 DOT files in the current directory.

Convert the DOT files to SVG with Graphviz by running `dot -Tsvg example.dot -o example.svg` on each DOT file.
These SVGs and DOTs should exactly match the files found in the `results` directory, which were used to create the figures in the paper.
