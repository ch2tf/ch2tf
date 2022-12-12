# CH2TF - Collaborative Heavy Hitter Traffic Filtering

---



## Installation
- This project has been tested with Python 3.10 and 3.11
  - Python < 3.10 is not supported due to use of match case statements
- `Dockerfile` runs with 3.11 (seems to perform better)


## Kafka & Zookeeper

- Docs
  - https://www.baeldung.com/ops/kafka-docker-setup
  - https://docs.confluent.io/5.5.4/quickstart/cos-docker-quickstart.html
- install with docker
- `export DOCKER_DEFAULT_PLATFORM=linux/amd64`
    `docker-compose -f docker-compose.yml up -d`
- Add topic
  `docker-compose exec kafka kafka-topics --create --bootstrap-server \
  localhost:9092 --replication-factor 1 --partitions 1 --topic testtopic`
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
