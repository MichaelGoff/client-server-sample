/**
 * This program will run an authenticated server that will keep track of
 * auctions. Uses multiple threads to connect to concurrent users.
 *
 * Michael Goff <magoff2 AT ncsu.edu>
 * 12/2/14
 * CSC 246
 */

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.Random;
import java.util.ArrayList;
import javax.crypto.Cipher;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.GeneralSecurityException;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.BadPaddingException;

/** A server that keeps up with a public key for every user, along with a current
    value for every user (whether or not they are connected.) */
public class Server {
  /** Port number used by the server */
  public static final int PORT_NUMBER = 26136;

  /** Record for an individual user. */
  private static class UserRec {
    // Name of this user.
    String name;

    // This user's public key.
    PublicKey publicKey;

    // This user's bid (zero by default).
    int bid = 0;
  }

  /**
   * This inner class will run the handleClient method for any client that
   * connects to the server.
   */
  private class ClientRunnable implements Runnable {
    /**
     * The socket the client connects with.
     */
    Socket sock;

    /**
     * This constructor will read in the socket passed from the server
     * @param  sock The socket to be stored.
     */
    public ClientRunnable(Socket sock) {
      this.sock = sock;
    }

    /**
     * This method will just call the outer classes handleClient method
     * so that the thread can properly interact with the client.
     */
    public void run() {
      try {
        Server.this.handleClient(sock);
      } catch(Exception e) {
        System.out.println("Decryption Exception thrown." + e);
        System.exit(1);
      }
    }
  }

  /** List of all the user records. */
  private ArrayList< UserRec > userList = new ArrayList< UserRec >();

  /** Read all user records. */
  private void readUserRecs() throws IOException, GeneralSecurityException {
    Scanner input = new Scanner( new File( "passwd.txt" ) );
    // While there are more usernames.
    while ( input.hasNext() ) {
      // Create a record for the next user.
      UserRec rec = new UserRec();
      rec.name = input.next();

      // Get the key as a string of hex digits and turn it into a byte array.
      String hexKey = input.nextLine().trim();
      byte[] rawKey = DatatypeConverter.parseHexBinary( hexKey );

      // Make a key specification based on this key.
      X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec( rawKey );

      // Make an RSA key based on this specification
      KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
      rec.publicKey = keyFactory.generatePublic( pubKeySpec );

      // Add this user to the list of all users.
      userList.add( rec );
    }
  }

  /** Handle interaction with a client. */
  private void handleClient( Socket sock ) throws Exception {
    try {
      // Get formatted input/output streams for this thread.
      DataOutputStream output = new DataOutputStream( sock.getOutputStream() );
      DataInputStream input = new DataInputStream( sock.getInputStream() );

      // Make a random challenge string.
      Random rand = new Random();
      StringBuilder challenge = new StringBuilder();
      for ( int i = 0; i < 20; i++ )
        challenge.append( (char)( 'a' + rand.nextInt( 26 )) );

      // Send the client the challenge string
      output.writeUTF( challenge.toString() );
      output.flush();

      // Get back the client's name and find the client in our list.
      String name = input.readUTF();

      // Find this user.
      UserRec rec = null;
      for ( int i = 0; rec == null && i < userList.size(); i++ )
        if ( userList.get( i ).name.equals( name ) )
          rec = userList.get( i );

      // True if the client successfully authenticates.
      boolean success = false;

      if ( rec != null ) {
        // Make a cipher object that will encrypt using this key.
        Cipher cipher = Cipher.getInstance( "RSA" );
        cipher.init( Cipher.DECRYPT_MODE, rec.publicKey );

        //reading in as a string of hex
        String msg = input.readUTF();

        // Convert the message to an array of bytes and encrypt it.
        byte[] rawMsg = DatatypeConverter.parseHexBinary( msg );
        byte[] rawDecrypt = {};
        try {
          rawDecrypt = cipher.doFinal( rawMsg );
        } catch (BadPaddingException e) {
          success = false;
        }

        //determining if the decryption is equal to the original challenge.
        if(challenge.toString().equals(new String(rawDecrypt))) {
          success = true;
        }
      }

      if ( success ) {
        // Tell the client they are authenticated.
        output.writeUTF( "success" );
        output.flush();

        // Get the first client command.
        String request = input.readUTF();
        Scanner requestScanner = new Scanner( request );

        // Parse out the first word and see what it is.
        String cmd = requestScanner.next();
        while ( ! cmd.equals( "done" ) ) {
          String response = null;

          // Figure out what the command is.
          if ( cmd.equals( "query" ) ) {
            // For query, just return our bid.
            response = String.format( "%d", rec.bid );
          } else if( cmd.equals("highest")) {
            int bid = -1;  //starting at -1 to be smaller than all other bids
            UserRec highest = null;
            //synchronized so only one thread may access the userList at a time.
            synchronized(this) {
              for(UserRec user : userList) {
                if(user.bid > bid) {
                  bid = user.bid;
                  highest = user;
                }
              }
            }
            response = highest.name + ": " + highest.bid;
          } else if (cmd.equals("set")) {
            response = rec.bid + " -> ";
            //synchronized so only one thread may edit a user at a time.
            synchronized(this) {
              //setting the bid to what user requested.
              rec.bid = requestScanner.nextInt();
            }
            response += "" + rec.bid;
          } else
            response = "invalid command";

          // Send the response back to our client.
          output.writeUTF( response );
          output.flush();

          // Get the next command.
          request = input.readUTF();
          requestScanner = new Scanner( request );
          cmd = requestScanner.next();
        }
      } else {
        output.writeUTF( "failure" );
        output.flush();
      }

      // We are done communicating with this client.
      sock.close();
    } catch ( IOException e ) {
      System.out.println( "Error interacting with client: " + e );
    }
  }

  /** Esentially, the main method for our server. */
  private void run( String[] args ) {
    ServerSocket serverSocket = null;

    // One-time setup.
    try {
      // Read records for all the users.
      readUserRecs();

      // Open a socket for listening.
      serverSocket = new ServerSocket( PORT_NUMBER );
    } catch( Exception e ){
      System.err.println( "Can't initialize server: " + e );
      System.exit( -1 );
    }

    // Keep trying to accept new connections and serve them.
    while( true ){
      try {
        // Try to get a new client connection.
        Socket sock = serverSocket.accept();

        // Interact with the new client.
        Thread clientThread = new Thread(new ClientRunnable(sock));
        clientThread.start();
      } catch( IOException e ){
        System.err.println( "Failure accepting client " + e );
      }
    }
  }

  public static void main( String[] args ) {
    // Make a server object, so we can have non-static fields.
    Server server = new Server();
    server.run( args );
  }
}
