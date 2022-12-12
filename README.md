# CH2TF - Collaborative Heavy Hitter Traffic Filtering

---


## Installation
- This project has been tested with Python 3.10 and 3.11
  - Python < 3.10 is not supported due to use of match case statements
- `Dockerfile` runs with 3.11 (seems to perform better)

### To run:

- Requires traffic files or sniffer
  - insert path in `.env` or in `docker-compose.yml`
- start ZooKeeper and Kafka:
  - `docker compose build`
  - `docker compose up zookeeper kafka`

While publishing a message in a non-existing topic creates the topic using this configuration,
in a 'fresh' install at the time of topic subscription it behaves differently.
Using this library, it does not subscribe to the topic if it does not exist yet.
The commands below create the default topics:
- `docker-compose exec kafka kafka-topics --create --bootstrap-server \
  localhost:9092 --replication-factor 1 --partitions 1 --topic lowprob.REQ`
- `docker-compose exec kafka kafka-topics --create --bootstrap-server \
  localhost:9092 --replication-factor 1 --partitions 1 --topic lowprob.RES`
- `docker-compose exec kafka kafka-topics --create --bootstrap-server \
  localhost:9092 --replication-factor 1 --partitions 1 --topic highprob.REQ`
- `docker-compose exec kafka kafka-topics --create --bootstrap-server \
  localhost:9092 --replication-factor 1 --partitions 1 --topic highprob.RES`

In subsequent 'runs', it is not necessary to use recreate the topics.


### Docker

- `docker compose up`


### Local:

- ensure python version >= 3.10 !
  - `python --version`
- `pip3 install -r requirements.txt`
- `export PYTHONPATH="\$\{PYTHONPATH\}:/src"`
- `python3 src/main.py`

#### IDE (IntelliJ / PyCharm):
- Edit Configurations:
  - select Python 3.10 or 3.11 interpreter
  - Script Path: .../src/main.py
  - Working Directory: .../src

#### Alternative (terminal, command line etc.):
- create new conda environment
- conda activate environment
- install requirements.txt into this new environment using conda
- `conda install python==3.11`



---
# Dev
### Code Format
- This project uses black for code formatting
  - `pip install black` or `mamba install black` (or conda etc.)
  - in directory: `black .`

### Typing
- This project uses `mypy` for static type checking
  - `pip install mypy` or `mamba install mypy` (or conda etc.)
  - in directory: `mypy .`
---

## License

The work of this thesis is multi-licensed under
- Apache License Version 2.0 (LICENSE.APACHE)
- MIT License (LICENSE.MIT)
- BSD 3-Clause License (LICENSE.BSD)

However, the evaluation and traffic generation modules (src/eval and src/traffic)
which are outside of the scope of ch2tf are licensed under
- GNU GENERAL PUBLIC LICENSE Version 2 (LICENSE.GPL)

These modules are for display purposes or evaluation purposes for the thesis only
and should not be treated as part of the prototype.
