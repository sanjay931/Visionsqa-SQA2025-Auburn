FROM continuumio/miniconda3

WORKDIR /app

RUN conda config --append channels conda-forge

# Create the environment:
COPY environment.yml .
RUN conda env create -v -f environment.yml

# Install additional packages directly into the KUBESEC environment
RUN conda install -n KUBESEC -y pandas
RUN conda run -n KUBESEC pip install ruamel.yaml sarif_om jschema-to-python typer

RUN apt-get update && apt-get install -y curl jq \
  && curl -L https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -o /usr/bin/yq \
  && chmod +x /usr/bin/yq

# Fix ENV format warning
ENV PATH=/opt/conda/envs/KUBESEC/bin:$PATH

# The code to run when container is started:
COPY constants.py graphtaint.py main.py parser.py scanner.py myLogger.py /app/
COPY TEST_ARTIFACTS/ /home/TEST_ARTIFACTS/

VOLUME ["/results"]

# This activates the conda environment before running the script
CMD ["conda", "run", "--no-capture-output", "-n", "KUBESEC", "python", "/app/main.py", "&&", "cp", "/home/slikube_results.csv", "/results/slikube_results.csv"]