---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

**Describe the bug**

A clear and concise description of what the bug is.

**To Reproduce**

1. Before you submit a bug, make sure that you are using the latest available version available at [Docker.com](https://hub.docker.com/r/chopicalqui/kali-intelligence-suite).
2. Provide the output of the following command so that we have information about the environment KIS is running:
    ```bash
    docker exec -it kaliintelsuite kismanage database --test
    ...
    ```
3. Provide relevant stack traces, which are stored in the Docker volume `kis_data`. You can access the relevant information by using the following commands:
    ```bash
    docker exec -it kaliintelsuite bash
    (.venv) kis_shell> vim /kis/kaliintelsuite.log
    ```
4. Provide all necessary KIS commands to reproduce the behavior:
    ```
    kismanage ...
    kiscollect ...
    ...
    ```

**Expected behavior**

A clear and concise description of what you expected to happen.

**Additional context**

Add any other context about the problem here.
