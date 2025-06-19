
# Compile


## Compile `client.cpp`

g++ client.cpp -o client -lssl -lcrypto


## Compile `sign_message.cpp`

g++ sign\_message.cpp -o sign\_message -lssl -lcrypto

## Compile the Enclave

cd sgx 

make clean && make 

# Run

## Run the Enclave

cd sgx 
./app

## Run the Client 

./client <hospital/lab>

## Sign messages 

./sign\_message <ecc_private_key> "<message>"

