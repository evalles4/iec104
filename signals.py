"""
Defines neccesary methods to work with signals.
Its use is deprecated since DASW manage its own signals.
"""
signals = []
def get_signals_conf():
    """
    Return the signals established.
    """
    global signals
    return signals
def set_signals_conf(signals_to_set):
    """
    Insert a new signal into the signals array.
    """
    global signals
    signals.append(signals_to_set)
def reset_signals_conf():
    """
    Reset the signals array.
    """
    global signals
    signals = []
def check_if_exist(signal):
    global signals
    return signal in signals

