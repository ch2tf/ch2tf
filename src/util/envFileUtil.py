def env_splitter(env_string: str) -> list:
    """

    :param env_string: a string from the env file that is to be interpreted as a list
    :return: list containing the multiple entries
    """
    return env_string.split(",")
