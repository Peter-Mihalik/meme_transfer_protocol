def main():
    hostname, port_main = '159.89.4.84', 42069
    # Main Chanell Communication
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_main:
        s_main.connect((hostname, port_main))
        # Init Comunication
        s_main.sendall(pynetstring.encode('C MTP V:1.0'))
        # Confirm Init
        confirmation = pynetstring.decode(s_main.recv(1024))[0].decode('utf-8')
        print(confirmation)
        # Send Nick
        s_main.sendall(pynetstring.encode('C peter_mihalik'))
        # Recieve token
        token = pynetstring.decode(s_main.recv(1024))[0].decode('utf-8').replace('S ', '')
        print('Token: ' + token)
        # Recieve port
        port_data = pynetstring.decode(s_main.recv(1024))[0].decode('utf-8').replace('S ', '')
        print('Port: ' + port_data)
    # Data Channel Communication
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_data:
        s_data.connect((hostname, int(port_data)))
        # Send Nick
        s_data.sendall(pynetstring.encode('C peter_mihalik'))
        # Recieve Token
        token_confirmation = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8').replace('S ', '')
        # Validate Token
        if token_confirmation == token:
            print(token_confirmation)
            # Recieve data request (MEME)
            data_req = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
            print(data_req)
            # Send Data (MEME)
            meme = base64.b64encode(open("meme.png", "rb").read()).decode("ascii")
            s_data.sendall(pynetstring.encode('C ' + meme))
            # Recieve Response (Data Lenght)
            meme_lenght = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
            print(meme_lenght)

            # Recieve data request PWD
            data_req = pynetstring.decode(s.recv(1024))[0].decode('utf-8')
            print(data_req)
            # Send Data
            s_data.sendall(pynetstring.encode('C 1234'))
            # Recieve Response (Data Lenght)
            pwd_lenght = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
            print(pwd_lenght)

            # Recieve data request Description
            data_req = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
            print(data_req)
            # Send Data
            s.sendall(pynetstring.encode('C no description here'))
            # Recieve Response (Data Lenght)
            desc_lenght = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
            print(desc_lenght)

            # Recieve data request NSFW
            data_req = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
            print(data_req)
            # Send Data
            s.sendall(pynetstring.encode('C false'))
            # Recieve Response (Data Lenght)
            nsfw_lenght = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
            print(nsfw_lenght)
            #Recieve dToken
            d_token = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8').replace('S END:', '')
            print(d_token)