#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>


#define TIME_STEP 30  // Default TOTP time step (30 seconds)

// to compile: gcc -o cloth cloth.c -lssl -lcrypto


/*
TODO
    - convert to work with a config file instead of prompting user
    - create better UI to allow for editing config file within the program
    - have all secrets have their TOTPs generate at the same time
        o format: service | totp
    - replace spinner with a loading bar
        - i spent so long trying to make a loading bar that i gave up a learned spinners
        - i am still mad i couldnt make it work

bugs:
    - spinner would sometimes show an extra /
        - spinner sometimes breaks prints right before it...?

    - remake this in python so it sucks less

*/




// Function to decode a Base32 encoded string into bytes
size_t base32Decode(const char* base32String, uint8_t** decodedBytes)  //note: uint8_t = byte (unsigned int length of 8 bits) 
{
    static const char base32CharList[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    size_t stringLen = strlen(base32String);                                    // Get input length
    size_t outputLen = (stringLen * 5 + 7) / 8;                                 // math to get output in bytes
    *decodedBytes = (uint8_t*)malloc(outputLen);                                // Memory allocation for decodedBytes



    size_t buffer = 0, leftBits = 0, byteCount = 0;
    for (size_t i = 0; i < stringLen; i++) 
    {
        char* charPosition = strchr(base32CharList, toupper(base32String[i]));      // Find the index of char
        if (charPosition == NULL) 
        {
            // Remove padding (=) and problematic characters
            if (base32String[i] == '=' || base32String[i] == '\n' || base32String[i] == '\r' || base32String[i] == ' ')
                continue;                                                           //If we find any of these characters, skip!
            printf("Invalid character: %c\n\n> > > Are you sure your secret is encoded in Base32?\n\n", base32String[i]);

            exit(1);
        }



        buffer <<= 5;                                                   // Bit shift left by 5
        buffer |= (charPosition - base32CharList) & 0x1F;               // Get value, add to buffer
        leftBits += 5;                                                  // Get 5 new bits

        

        if (leftBits >= 8) 
        {                                                       // output a byte
            (*decodedBytes)[byteCount++] = (buffer >> (leftBits - 8)) & 0xFF;     // Extract the byte
            leftBits -= 8;                                                         // Decrease the number of bits left
        }
    }

    return byteCount;  // Return the number of bytes decoded
}



// Function to compute the HMAC-SHA1 digest using a key and data
void computeHMAC(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen, uint8_t* HMAC_Result) 
{
    unsigned int HMAC_Len;
    HMAC(EVP_sha1(), key, keyLen, data, dataLen, HMAC_Result, &HMAC_Len);  // Compute the HMAC-SHA1
}

// Function to generate the Time-based One-Time Password (TOTP)
uint32_t generateTOTP(const uint8_t* key, size_t keyLen, uint64_t timeCounter) 
{
    uint8_t counterBytes[8];   // Store byte counter (8 bytes)
    uint8_t HMAC_Result[20];   // Create hash through HMAC

    // Convert the counter to an 8-byte int
    for (int i = 7; i >= 0; i--) 
    {
        counterBytes[i] = timeCounter & 0xFF;   // Bitwise AND op
        timeCounter >>= 8;                      // Shift rigtht 8 bits
    }

    // Generating HMAC-SHA1 
    computeHMAC(key, keyLen, counterBytes, sizeof(counterBytes), HMAC_Result);

    // Truncating for 4 byte chunk of the HMAC
    int offset = HMAC_Result[19] & 0x0F;            // Bitwise AND last 4 bits of HMAC result
    uint32_t truncHash = (HMAC_Result[offset] & 0x7F) << 24 |
        (HMAC_Result[offset + 1] & 0xFF) << 16 |
        (HMAC_Result[offset + 2] & 0xFF) << 8 |     // https://datatracker.ietf.org/doc/html/rfc4226#section-5.4
        (HMAC_Result[offset + 3] & 0xFF);           // Extract the 4 bytes

    return truncHash % 1000000;  // Return the last 6 digits
}




int main() 
{

    //variable delcarations
    char base32Secret[256];     // To store the input Base32 secret key
    uint8_t* decodedSecret;     // Store decoded secret
    size_t secretLen;           // Length of (decoded) key

    int debug = 0;             

    //ascii art
    printf("\n\n++----------------------------------++\n");
    printf("++----------------------------------++\n");
    printf("||    ____ _     ___ _____ _   _    ||\n");
    printf("||   / ___| |   / _ \\_   _| | | |   ||\n");
    printf("||  | |   | |  | | | || | | |_| |   ||\n");
    printf("||  | |___| |__| |_| || | |  _  |   ||\n");
    printf("||   \\____|_____\\___/ |_| |_| |_|   ||\n");
    printf("||                                  ||\n");
    printf("++----------------------------------++\n");
    printf("++----------------------------------++\n\n");



    // Welcome message
    printf("Welcome to CLOTH, a CLI-based TOTP Generator!\n");
    printf("Press Ctrl+C to exit.\n\n");

    // Ask for user input [only Base32 works right now,]
    printf("Enter your Base32 secret key: ");
    fgets(base32Secret, sizeof(base32Secret), stdin);
    


    // start decoding base32Secret, save number of bytes to length
    secretLen = base32Decode(base32Secret, &decodedSecret);

    printf("Generating TOTPs using secret key: %s\n\n", base32Secret);  // Show the entered secret key
    //printf("debug: %hhu", &decodedSecret);
    


    //=======================
    //      Spinner code    
    //=======================

    // Spinner characters for waiting display
    char spinner[] = {'\\', '|', '/', '-'};
    int spinnerCount = 0;  // To cycle through the spinner characters

    while (1) 
    {
        // Get current time
        uint64_t currentTime = (uint64_t)time(NULL);  // Getting UNIX time
        uint64_t timeCounter = currentTime / TIME_STEP;  // time/timestep (30) = time counter (which starts ticking down)

        
        uint32_t totp = generateTOTP(decodedSecret, secretLen, timeCounter);                    // Generate the TOTP 
        int timeRemaining = TIME_STEP - (currentTime % TIME_STEP);                              // Calculate remaining time for step
        
        printf("\rTOTP: %06u (Valid for %ds) %c", totp, timeRemaining, spinner[spinnerCount]);  // Display TOTP and the time remaining
        
        fflush(stdout); // If you don't do this everything breaks :(

        
        spinnerCount = (spinnerCount + 1) % 4;      // Update spinner index to cycle through the characters
        sleep(1);                                   // Wait a second to sync with the TOTP second counter
    }



    return 0;
}
