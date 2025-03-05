import re

def validate_docker_image_name(image_name):
    """
    Validate the docker image name format.
    """
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9._-]*)(/[a-zA-Z0-9]([a-zA-Z0-9._-]*))*(:[\w][\w.-]{0,127})?$'
    return bool(re.match(pattern, image_name))
