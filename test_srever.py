import socket
import time
import pynetstring
import base64


def server_comunication(nick_name: str, pwd:str, desc:str, nsfw: bool, meme_path:str) -> str:
    hostname, port_main = '159.89.4.84', 42069
    # Main Chanell Communication
    # Main Chanell Communication
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_main:
        s_main.connect((hostname, port_main))
        # Init Comunication
        s_main.sendall(pynetstring.encode('C MTP V:1.0'))
        print('Client:  ' + 'C MTP V:1.0')
        # Confirm Init
        confirmation = pynetstring.decode(s_main.recv(1024))[0].decode('utf-8')
        if confirmation == 'S MTP V:1.0':
            print('Server:  ' + confirmation)
            # Send Nick
            s_main.sendall(pynetstring.encode('C ' + nick_name))
            print('Client:  ' + 'C ' + nick_name)
            # Recieve token
            token_response = pynetstring.decode(s_main.recv(1024))[0].decode('utf-8')
            if 'S ' in token_response:
                token = token_response.replace('S ', '')
                print('Server:  ' + token_response)
                # Recieve port
                port_response = pynetstring.decode(s_main.recv(1024))[0].decode('utf-8')
                if 'S ' in port_response:
                    port_data = port_response.replace('S ', '')
                    print('Server:  ' + port_response)
                    # Data Channel Communication
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_data:
                        try:
                            s_data.connect((hostname, int(port_data)))
                        except:
                            return 'Server Error! (Unable to connect to Data Chanell)'
                        # Send Nick
                        s_data.sendall(pynetstring.encode('C ' + nick_name))
                        print('Client:  ' + 'C ' + nick_name)
                        # Recieve Token
                        token_verefication_response = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
                        if 'S ' in token_verefication_response:
                            token_verefication = token_verefication_response.replace('S ', '')
                            print('Server:  ' + token_verefication_response)
                            # Validate Token
                            if token_verefication == token:
                                # Recieve data request (MEME)
                                data_req = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
                                print('Server:  ' + data_req)
                                # Send Data (MEME)
                                meme = base64.b64encode(open(meme_path, "rb").read()).decode("ascii")
                                s_data.sendall(pynetstring.encode('C ' + meme))
                                print('Client:  ' + 'C <meme>')
                                # Recieve Response (Data Lenght)
                                meme_lenght = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8').replace('S ACK:', '')
                                print('Server:  S ' + meme_lenght)

                                # Recieve data request PWD
                                data_req = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
                                print('Server:  ' + data_req)
                                # Send Data
                                s_data.sendall(pynetstring.encode('C ' + pwd))
                                print('Client:  C <password>')
                                # Recieve Response (Data Lenght)
                                pwd_lenght = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8').replace('S ACK:', '')
                                print('Server:  S ' + pwd_lenght)

                                # Recieve data request (Description)
                                data_req = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
                                print('Server:  ' + data_req)
                                # Send Data
                                s_data.sendall(pynetstring.encode('C ' + desc))
                                print('Client:  ' + 'C ' + desc)
                                # Recieve Response (Data Lenght)
                                desc_lenght = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8').replace('S ACK:', '')
                                print('Server:  S ' + desc_lenght)

                                # Recieve data request (NSFW)
                                data_req = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
                                print('Server:  ' + data_req)
                                # Send Data
                                s_data.sendall(pynetstring.encode('C ' + str(nsfw).lower()))
                                print('Client:  C ' + str(nsfw).lower())
                                # Recieve Response (Data Lenght)
                                nsfw_lenght = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8').replace('S ACK:', '')
                                print('Server:  S ' + nsfw_lenght)
                                #Recieve dToken
                                d_token_response = pynetstring.decode(s_data.recv(1024))[0].decode('utf-8')
                                d_token = d_token_response.replace('S END:', '')
                                print('Server:  ' + d_token_response)
                            else:
                                return 'Server Error! (Tokens doesn\'t match)'
                            # Recieve Response (Finall Lenght)
                            finall_lenght_response = pynetstring.decode(s_main.recv(1024))[0].decode('utf-8')
                            if not 'S ' in  finall_lenght_response:
                                return 'Server Error! ' + finall_lenght_response
                            finall_lenght = finall_lenght_response.replace('S ', '')
                            print('Server:  '+ finall_lenght_response)
                            sum_lenght = int(meme_lenght) + int(pwd_lenght) + int(desc_lenght) + int(nsfw_lenght)
                            if int(finall_lenght) == sum_lenght:
                                # Send dToken
                                s_main.sendall(pynetstring.encode('C ' + d_token))
                                print('Client:  ' + 'C ' + d_token)
                                # Recieve End Message
                                end_msg = pynetstring.decode(s_main.recv(1024))[0].decode('utf-8')
                                if end_msg == 'S ACK':
                                    print(end_msg)
                                    return 'Meme Uploaded Successfully!!!'
                                else:
                                    return 'Server Error! ' + end_msg 
                            else:
                                print(str(finall_lenght) + '!=' + str(sum_lenght))
                                return 'Server Error! (Data Corruption)'
                        else:
                            return 'Server Error! ' + token_verefication_response
                else:
                    return 'Server Error! ' + port_response
            else:
                return 'Server Error! ' + token_response
        else:
            return 'Server Error!' + confirmation

def main():
    print(server_comunication('peter_mihalik', '1234', 'no descriptio here', False, 'meme.png'))


if __name__ == '__main__':
    main()