import web
import os
from Hashes import SHA1

urls = (
    "/", "hello",
    "/test", "test",
    "/stop", "stop"
)

key = 0

class hello:
    def GET(self):
        return "Hello, world!"

class test:
    def GET(self):
        user_data = web.input(file = None, signature = None)

        file_name = user_data.file
        signature = user_data.signature

        file_sig = 0

        with open(file_name) as file:
            contents = bytearray(file.read())
            file_sig = 0

        return file_name

class stop:
    def GET(self):
        app = web.application(urls, globals())
        app.stop()


if __name__ == "__main__":

    key = os.urandom(32)

    app = web.application(urls, globals())
    app.run()