from socket import *
import threading
from sys import argv
import time


serverIP = argv[1]          
serverPort = int(argv[2])   #Using port 9292

clientSock = socket(AF_INET, SOCK_STREAM)
clientSock.connect((serverIP,serverPort))

def getLine(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode().strip()

#Listener
def Listener():
    while True:
        incomingMessage = getLine(clientSock).strip()

        if incomingMessage.startswith("(K)") or incomingMessage.startswith("(B)"):
            time.sleep(1)
            exit()
        else:
            print(f"\r{incomingMessage}\n>> ", end="", flush=True)

   

# Constructs the username and password to send to server
# It will then be validated and if successful, will display MOTD
def login(username, password):
    message = username + " " + password + "\n"
    clientSock.send(message.encode())
    
    response = getLine(clientSock)
    
    print(response)
    if response.startswith("Error: The username"):
        return False
    if response.startswith("Incorrect"):
        return False
    if response.startswith("You are banned"):
        return False
    else:
        return True



def main():
    username = input("Please enter your Username:")
    password = input("Please enter your Password:")

    # If the connection is not forcibly closed by server it will
    # reach this point
    if login(username,password):

        listenThread = threading.Thread(target=Listener, daemon=True).start()


        while True:
            try:
                command = input(">> ") + "\n"
                clientSock.send(command.encode())
                # Able to recieve messages back from server
                #response = getLine(clientSock).strip()
                #print(response)

                match command.strip():
                    case "/exit":
                        print("Exiting chatroom...")
                        return
            except:
                print("Exiting Program...")
                listenThread.join()
                clientSock.close()
                return




if __name__ == "__main__":
    main()
