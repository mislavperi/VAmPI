class SimpleCache:
    def __init__(self):
        self.cache = {}

    def set(self, key, value):
        self.cache[key] = value

    def get(self, key):
        return self.cache.get(key, None)

    def delete(self, key):
        if key in self.cache:
            del self.cache[key]

