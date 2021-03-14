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
    def GET(self):
        user_data = web.input(file = None, signature = None)

        file_name = user_data.file
        signature = bytearray.fromhex(user_data.signature)

        verified = False


        with open(file_name) as file:

            global key
            contents = bytearray(file.read(),'utf-8')
            
            verified = SHA1.insecure_compare(contents,key,signature)

        if verified == False:
            web.HTTPError("500")
            return 500
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