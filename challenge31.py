import web
import os
from Hashes import SHA1

urls = (
    "/", "hello",
    "/test", "test",
    "/stop", "stop"
)

key = b'abcdefghijklmnop'

class hello:
    def GET(self):
        return "Hello, world!"

class test:

    files = {}

    def GET(self):
        user_data = web.input(file = None, signature = None)

        file_name = user_data.file
        signature = bytearray.fromhex(user_data.signature)

        verified = False

        if file_name not in test.files.keys():
            with open(file_name) as file:

                test.files[file_name] = bytearray(file.read(),'utf-8')

        global key
        verified = SHA1.insecure_compare(test.files[file_name],key,signature)

        if verified == False:
            web.HTTPError("500")
            return signature
        else:
            web.HTTPError("200")
            return 200

        return file_name

class stop:
    def GET(self):
        app = web.application(urls, globals())
        app.stop()


if __name__ == "__main__":

    #key = os.urandom(32)
    key = b'abcdefghijklmnop'

    app = web.application(urls, globals())
    app.run()