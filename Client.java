/**
 * This is a client that will connect to the auction server. It will
 * authenticate itself before interactions will be allowed.
 *
 * Michael Goff <magoff2 AT ncsu.edu>
 * 12/2/14
 * CSC 246
 */

import java.io.*;
import java.util.Scanner;
import java.net.Socket;
import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.GeneralSecurityException;
import javax.xml.bind.DatatypeConverter;

/** Client supporting simple interactionw with the server. */
public class Client {
  public static void main( String[] args ) throws Exception {
    // Complain if we don't get the right number of arguments.
    if ( args.length != 1 ) {
      System.out.println( "Usage: ExampleClient <host>" );
      System.exit( -1 );
    }

    try {
      // Try to create a socket connection to the server.
      Socket sock = new Socket( args[ 0 ], Server.PORT_NUMBER );

      // Get formatted input/output streams for this thread.
      DataInputStream input = new DataInputStream( sock.getInputStream() );
      DataOutputStream output = new DataOutputStream( sock.getOutputStream() );

      // Get a username from the user.
      Scanner scanner = new Scanner( System.in );
      System.out.print( "Username: " );
      String name = scanner.nextLine();

      // Get the challenge string.
      String challenge = input.readUTF();

      // Send the username for this client.
      output.writeUTF( name );
      output.flush();

      //reading the private key from the user.txt file.
      Scanner keyScanner = new Scanner( new File( name + ".txt" ) );
      String hexKey = keyScanner.nextLine();
      byte[] rawKey = DatatypeConverter.parseHexBinary( hexKey );

      // Make a key specification based on this key.
      PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec( rawKey );

      // Get an RSA key based on this specification
      KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
      PrivateKey privateKey = keyFactory.generatePrivate( privKeySpec );

      // Make a cipher object that will encrypt using this key.
      Cipher cipher = Cipher.getInstance( "RSA" );
      cipher.init( Cipher.ENCRYPT_MODE, privateKey );

      // Convert the message to an array of bytes and encrypt it.
      byte[] rawMsg = challenge.getBytes();
      byte[] rawEncrypt = cipher.doFinal( rawMsg );

      //send the encrypted challenge string as hex
      output.writeUTF(DatatypeConverter.printHexBinary( rawEncrypt ));
      output.flush();

      String response = input.readUTF();
      if ( response.equals( "success" ) ) {
        // Read commands from the user and print server responses.
        String request = "";
        System.out.print( "cmd> " );
        while ( scanner.hasNextLine() && ! ( request = scanner.nextLine() ).equals( "done" ) ) {
          output.writeUTF( request );
          output.flush();

          // Read and print the response.
          response = input.readUTF();
          System.out.println( response );

          System.out.print( "cmd> " );
        }

        // Send the done command to the server.
        output.writeUTF( request );
        output.flush();
      } else {
        System.out.println( "Authentication failure" );
      }

      // We are done communicating with the server.
      sock.close();
    } catch( IOException e ){
      System.err.println( "Can't communicate with server: " + e );
    }
  }
}
