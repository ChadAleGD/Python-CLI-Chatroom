from socket import *
import sys
import threading
import hashlib
from collections import deque
import time


port = 9292

failed_logins = {}

blocked_logins = {}
# Key = username | Value = Client Socket
connectedClients = {}

# Key = username | Value = password
clientAccounts = {}

# Commands avaliable
commands = ["/who : Displays a list of all users that are currently connected to the server",
            "/MOTD : Displays the current Message of the Day",
            "/tell : Send a direct message to a username | Format: /tell username [message]",
            "/me :  Sends an emote message",
            "/help : Gives list of commands avaliable",
            "/exit : Disconnects user from chatroom"]

connectedListLock = threading.Lock()

listener = socket(AF_INET, SOCK_STREAM)
listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
listener.bind(('', port))
listener.listen(32)

MESSAGE_OF_THE_DAY = ("Welcome to our chatroom!\n").encode()

# Key = username | Value = Dictionary {Incoming user, list of messages}
OFFLINE_MESSAGES = {}

offlineListLock = threading.Lock()

BANNED_USERS = []

ADMIN = None
adminQueue = deque()


#----------------------------------------------------------------------------------------------#



# Loads all accounts in accounts.txt
def load_accounts():
    try:
        with open("accounts.txt", "r") as f:
            for line in f:
                line = line.strip()
                if not line:  
                    continue
                parts = line.split()
                if len(parts) == 2:  # Ensure we have both username and password
                    username, password = parts
                    clientAccounts[username] = password
    except FileNotFoundError:
        pass

# Saves Accounts to accounts.txt
def save_accounts():
    with open("accounts.txt", "w") as f:
        for username, password in clientAccounts.items():
            f.write(f"{username} {password}\n")

def GetLine(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode()

# /who command call
def who(clientConn):
    connected_users = list(connectedClients.keys())
    message = "Currently connected users: " + ",".join(connected_users) + "\n"
    clientConn.send(message.encode())

# Format: /tell username "message"
def tell(clientConn: socket, username, message):

    #If the user exists then send the message
    if username in clientAccounts:

        sender = next((k for k, v in connectedClients.items() if v == clientConn), None)

        # Case if user is online
        if username in connectedClients:
            # If user is online send the message now
            connectedListLock.acquire()
            newMessage = f"From {sender}: {message}" 
            connectedClients[username].send((f"\033[32m{newMessage}\033[0m" + '\n').encode())  
            connectedListLock.release()


        # Else Save the message for the next time they login
        else:
            print("Adding message to offline...")

            offlineListLock.acquire()
            if username not in OFFLINE_MESSAGES:
                OFFLINE_MESSAGES[username] = {}
            
            if sender not in OFFLINE_MESSAGES[username]:
                OFFLINE_MESSAGES[username][sender] = []

            OFFLINE_MESSAGES[username][sender].append((message + '\n'))
            offlineListLock.release()



    # Else report an error back
    else:
        print("User attempted bad /tell")
        clientConn.send(("Error! " + username + " not found!\n").encode())


def kick(target: str):
    if target in connectedClients:
        connectedClients[target].send(("(K) ADMIN: You have been kicked.\n").encode())
        time.sleep(1)
        RemoveClient(target)

def unban(target: str):
    global BANNED_USERS

    BANNED_USERS.remove(target)

def ban(target: str):
    global BANNED_USERS

    if target in connectedClients:
        connectedClients[target].send(("(B) ADMIN: You have been banned!\n").encode())
        time.sleep(1)
        RemoveClient(target)

    BANNED_USERS.append(target)


# /MOTD command
def SendMOTD(clientConn: socket):
    clientConn.send(MESSAGE_OF_THE_DAY)

# Updates the /MOTD command to a new message
def updateMOTD(message):
    global MESSAGE_OF_THE_DAY
    MESSAGE_OF_THE_DAY = message


def me(username, message):
    #Get current username of user
    new_message = "*" + username +" " + message
    # Format to print: *username message
    send_to_all(username,new_message)

def help(clientConn):
    sorted_commands = sorted(commands, key=lambda cmd: cmd.split(' ', 1)[0].lower())
    message = "The available commands are:\n" + "\n".join(sorted_commands)
    clientConn.sendall(message.encode())
    
def send_to_all(senders_username, message):
    # Create a message that includes the sender's username
    full_message = f"{senders_username}: {message}" + "\n"

    # Iterate through all connected clients and send the message
    for username, clientConn2 in connectedClients.items():
        if username != senders_username:  # Avoid sending the message back to the sender
            try:
                clientConn2.sendall(full_message.encode())  # Send the message to each client
            except Exception as e:
                print(f"Error sending message to {username}: {e}")


def RemoveClient(clientUsername):
    global ADMIN

    connectedClients[clientUsername].close()

    connectedListLock.acquire()
    del connectedClients[clientUsername]
    connectedListLock.release()

    if clientUsername in adminQueue:
        adminQueue.remove(clientUsername)

    if ADMIN == clientUsername:
        if adminQueue:
            ADMIN = adminQueue.popleft()
            print(f"{ADMIN} is now the new admin.")
        else:
            ADMIN = None
            print(f"No admin appointed. Waiting for new user connection.")

    print(f"\033[31m{clientUsername} has disconnected.\033[0m")


# TODO: If the client succesfully connects, then server needs to send each offline message designated to them
def HandleClient(connInfo):
    global ADMIN
    global BANNED_USERS

    clientConn, clientAddr = connInfo
    clientIP = clientAddr[0]

    if clientIP in blocked_logins and time.time() < blocked_logins[clientIP]:
        clientConn.send("Too many failed Attempts. Try again later.\n".encode())
        clientConn.close()
        return
    print(f"New client detected, {clientIP} : {clientAddr[1]}")

    clientUsername, clientPassword = GetLine(clientConn)[:-1].split(' ')


    if clientUsername in BANNED_USERS:
        clientConn.send(("You are banned! You cannot connect to this chatroom...\n").encode())
        clientConn.close()
        return


    if clientUsername in connectedClients:
        # If the username is in use, reject the login
        clientConn.send((f"Error: The username '{clientUsername}' is already logged in. Please try again later.\n").encode())
        clientConn.close()
        return
    
    # Validate the username and password
    if clientUsername not in clientAccounts:
        connectedListLock.acquire()
        clientAccounts[clientUsername] = clientPassword
        connectedClients[clientUsername] = clientConn
        connectedListLock.release()
        save_accounts()
    else:
        if clientUsername not in clientAccounts or clientPassword != clientAccounts[clientUsername]:
            clientConn.send((f"Incorrect password for user: {clientUsername}\n").encode())
            # Record failed attempt
            if clientIP not in failed_logins:
                failed_logins[clientIP] = []
            
            failed_logins[clientIP].append(time.time())
            # Remove old failed attempts (older than 30 seconds)
            failed_logins[clientIP] = [t for t in failed_logins[clientIP] if time.time() - t < 30]
            # If 3 or more failed attempts in 30 seconds, block the IP
            if len(failed_logins[clientIP]) >= 3:
                blocked_logins[clientIP] = time.time() + 120  # Block for 2 minutes
                del failed_logins[clientIP]  # Clear failed attempts after blocking
                clientConn.send("Too many failed attempts. You are temporarily blocked.\n".encode())
            clientConn.close()
            return
        else:
            connectedListLock.acquire()
            connectedClients[clientUsername] = clientConn
            connectedListLock.release()


    adminQueue.append(clientUsername)

    if ADMIN == None:
        ADMIN = adminQueue.popleft()
        print(f"{clientUsername} is the current admin")



            
   
    connectionMessage = clientUsername + " has connected to the chatroom."
    send_to_all("Server",connectionMessage)

    try:
        SendMOTD(clientConn)
        # Check DM GOES HERE

        # Send all the offline messages assigned to user
        offlineListLock.acquire()

        if clientUsername in OFFLINE_MESSAGES and OFFLINE_MESSAGES[clientUsername]:            
            for sender, messages in OFFLINE_MESSAGES[clientUsername].items():
                clientConn.send(f"Offline messages from: {sender} \n".encode())

                for message in messages:
                    clientConn.send(f"{message}\n".encode())

            OFFLINE_MESSAGES[clientUsername].clear()

        offlineListLock.release()


        clientConnected = True
        while clientConnected:
            userInput = GetLine(clientConn).strip()
            startingWord = userInput.split()[0] #Grabs the first word in the command
            
            # Switch statment that handle / commands
            match startingWord:
                case "/who":
                    who(clientConn)
                case "/MOTD":
                    SendMOTD(clientConn)
                case "/tell":
                    # Grabs username and Message
                    username = userInput.split()[1]
                    message = " ".join(userInput.split()[2:])
                    # Sends username and Message to DM 
                    # which sends it to the corresponding user
                    tell(clientConn, username, message)
                case "/me":
                    message = " ".join(userInput.split()[1:])
                    me(clientUsername,message)
                case "/help":
                    help()
                case "/ban":
                    target = userInput.split()[1]
                    if clientUsername == ADMIN:
                        clientConn.send(("User has been banned.\n").encode())
                        ban(target)
                    else:
                        clientConn.send(("You do not have permissions to use that command!\n").encode())
                case "/unban":
                    target = userInput.split()[1]
                    if clientUsername == ADMIN:
                        unban(target)
                    else:
                        clientConn.send(("You do not have permissions to use that command!\n").encode())
                case "/kick":
                    target = userInput.split()[1]
                    if clientUsername == ADMIN:
                        kick(target)
                    else:
                        clientConn.send(("You do not have permissions to use that command!\n").encode())
                case "/exit":
                    clientConnected = False
                case _:
                    send_to_all(clientUsername,userInput)
                    
            

    except Exception as e:
        print(e) # Gives info on exceptions
        print("Error, closing connection")
        clientConnected = False

    clientConn.close()
    RemoveClient(clientUsername)

# First make sure to run a persistent data load

load_accounts()
running = True
while running:
    try:
        threading.Thread(target=HandleClient, args=(listener.accept(),), daemon=True).start()
    except KeyboardInterrupt:
        print('\n[Shutting down]')
        running = False
