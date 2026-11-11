from teralibs.terasploit.framework.encoder.factory import EncoderFactory


def reset_encoder_factory():
    """
    Reset the EncoderFactory's auto-discovery cache.

    This function clears the cached list of discovered encoders, forcing
    the EncoderFactory to re-scan the modules directory for new encoders
    on the next use. It is useful when new encoder modules have been added
    to the framework while it is running.

    NOTE: This was created to avoid the risk of circular import.
    """
    EncoderFactory.reset()
