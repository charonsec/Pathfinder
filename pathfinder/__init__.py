from .detector import PathFinderDetector

def make_plugin():
    # Return (detector list, printer list)
    return [PathFinderDetector], []