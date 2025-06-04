import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;



public class AllQuestions {

        static BigInteger p = new BigInteger("15554903035303856344007671063568213071669822184616101992595534860863803506262760067615727000088295330493705796902296102481798240988227195060316199080930616035532980617309644098719341753037782435645781436420697261984870969742096465765855782491538043554917285285471407866976465359446400695692459955929581561107496250057761324472438514351159746606737260676765872636140119669971105314539393270612398055538928361845237237855336149792618908050931870177925910819318623");
        static BigInteger q = new BigInteger("15239930048457525970295803203207379514343031714151154517998415248470711811442956493342175286216470497855132510489015253513519073889825927436792580707512051299817290925038739023722366499292196400002204764665762114445764643179358348705750427753416977399694184804769596469561594013716952794631383872745339020403548881863215482480719445814165242627056637786302612482697923973303250588684822021988008175106735736411689800380179302347354882715496632291069525885653297");

    public static void main(String[] args) {
        
          Scanner scanner = new Scanner(System.in);
        System.out.print("\nQuestion 1 : RSA Encryption and Decryption ");
        System.out.print("\nQuestion 2 : Cracking Credit card");
        System.out.print("\nQuestion 3 : Comparing RSA and AES time: ");
        System.out.print("\n\nEnter number for question to be run : ");
        int input = scanner.nextInt();

        scanner.close();

        BigInteger phi = (p.subtract(new BigInteger("1"))).multiply(q.subtract(new BigInteger("1")));
        BigInteger ePub,dPrivate = BigInteger.ZERO; // Common public exponent
        BigInteger res=BigInteger.ZERO;

        switch (input) {
            case 1:
                String randomPlaintext = generateRandomPlaintext(16);
                do {
                    Random random = new Random();
                    
                    ePub = BigInteger.valueOf(random.nextInt(65537));
                    try {
                        dPrivate = ePub.modInverse(phi);
                        res = ePub.multiply(dPrivate).mod(phi);
                        
                    } catch (ArithmeticException e) {
                        continue;
                    }
                } while (!res.equals(BigInteger.ONE));
                
                BigInteger n = p.multiply(q);

                // Encrypt the message
                byte[] bytes = randomPlaintext.getBytes();
                BigInteger plaintext = new BigInteger(bytes);
                BigInteger ciphertext = plaintext.modPow(ePub, n);

                // Decrypt the message
                BigInteger plaintext_m = ciphertext.modPow(dPrivate, n);
                String plaintext_new = new String(plaintext_m.toByteArray());



                System.out.print("\n\n The first prime is p = "+p);
                System.out.print("\n\n The second prime is q = "+q);
                System.out.print("\n\n The composite modulus n = "+n);
                System.out.print("\n\n The encryption exponent e = "+ePub);
                System.out.print("\n\n The decryption exponent d = "+dPrivate);
                System.out.println("\n\n-------------- ");
                System.out.println("\n\nEncryption ");
                System.out.println("\n\nPlaintext (randomly generate) to be encrypted is m = "+ randomPlaintext);
                System.out.println("\n\nCiphertext is c = " + ciphertext.toString());
                System.out.println("\n\n-------------- ");
                System.out.println("\n\nDecryption ");
                System.out.println("\n\nCiphertext to be decrypted is c = "+ ciphertext.toString());
                System.out.println("\nDecrypted plaintext is m = " + plaintext_new.toString());


                break;

            case 2:
                BigInteger N= new BigInteger("460715399001559730200601166413343637768942051220480370462632493575191669384732250446893196360704197534568792671939136603673725514114188867897475714684282463308321544148682297079283463625678958237605023210457026820438645129274979026460998182524351770627262105263100974253602029420136575068052360114827691317472360169797361866212038664960246439105442914003067162669581739537173839028790054808273341208897316847166651901457303733150546502525250824699006784152358574104315242517584825147004821128289626577001576661904416568458461710573427170439027647979329729119398418942702971906937330310594255299111766728510520678762910887830925908223981236256377008400479814008708835196512771544027282713903013676662513648305366192220799601824182387485040055196216936365391890056761764702267288334221936841637639129355682535037878129087951601000676650532612069347421067601833002522375047392556876161230004701730394090614742213598145891239");
                BigInteger ea= new BigInteger("65537");
                BigInteger eb= new BigInteger("65539");
                BigInteger ca= new BigInteger("89745274411354037741574448673658487065208180022243288525981160800449095235901677097513383012540032346283953189863061675936739427912215438860532640318594720396516548337307397226298374547287596636615861368984331445045328707490128371063412568188735656660699244767615597885268600327598873509580126320519945458628124508698819858986114698093531890194029335302867638174697097148507460901602925425387863897923383252117030747454358800335426883140699178484748052966252681548180850880797261400509874920122979964827135637915358636532088222057602826669817249756696270881992513332720759139844602463315224724434502326691456295873082683551428116010953103271686356160686653120943811896279012915210874508415695494038456537233510665500596669495949123928314468937354517985826129529442700098031287498802465969899286695615955900516205858147074365724103307354824633035929088425897478035611149971777058966650698784623116834891416817231967554332");
                BigInteger cb= new BigInteger("64672434483882461197730449972631380268311158055228702395507684291937238289559922465679151846830440225291345678962039222670484403723017402390330172026773124600110978255007239806283820416824494761942866932360626343148614051642375854423995051307729805291784383279657156470539473607532431736348190577278141611293548905363555101216387453601895188517091462028615026933764170226880044925280759809483903795425318957029462785485146342817640919624239802496454734536364397189110473261160684384371561058889938514397146562924621139693563707912796878570625641551698392191395017878281598130380233705508113339307042583381329736043772827508993161755492930296363424990139576514800412088984148946474479820281112781322728909762310061303126985670516359436112639793300323666669681500344056729700421747411968301533365037159935963541696147434973357500669634309118138685291028153847392853890726563339187964595380466023713492302411167729571747842");
         
                BigInteger d, r, s;
                BigInteger[] array = computeEC(ea, eb);
                d = array[0];
                r = array[1];
                s = array[2];
                
                BigInteger c1 = ca.modPow(r, N);
                BigInteger c2 = cb.modPow(s, N);
                
                BigInteger m = c1.multiply(c2).mod(N);                    
                
                System.out.print("Credit card number = "+ m +"\n\n");           
                break;

                case 3:
                    try {
                        BigInteger p = new BigInteger("15554903035303856344007671063568213071669822184616101992595534860863803506262760067615727000088295330493705796902296102481798240988227195060316199080930616035532980617309644098719341753037782435645781436420697261984870969742096465765855782491538043554917285285471407866976465359446400695692459955929581561107496250057761324472438514351159746606737260676765872636140119669971105314539393270612398055538928361845237237855336149792618908050931870177925910819318623");
                        BigInteger q = new BigInteger("15239930048457525970295803203207379514343031714151154517998415248470711811442956493342175286216470497855132510489015253513519073889825927436792580707512051299817290925038739023722366499292196400002204764665762114445764643179358348705750427753416977399694184804769596469561594013716952794631383872745339020403548881863215482480719445814165242627056637786302612482697923973303250588684822021988008175106735736411689880380179302347354882715496632291069525885653297");
                        BigInteger e = new BigInteger("65537");

                        BigInteger nPubBigInteger = p.multiply(q);


                        int dataSize = 10 * 1024 * 1024;
                    
                        byte[] data = new byte[dataSize];
                        new SecureRandom().nextBytes(data);

                        long timeStart = System.nanoTime();

                        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                        keyGen.init(128); //block size of AES
                        SecretKey aesKey = keyGen.generateKey();

                        AESEncrypt(aesKey, data);

                        long aesTimeEnd = System.nanoTime()-timeStart;
                        
                        System.out.println("The AES cipher time (nano second): " + String.valueOf(aesTimeEnd) + " ---> (Milisecond) : " + String.valueOf(aesTimeEnd/1000000));

                        timeStart = System.nanoTime();

                        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
                        keyPairGen.initialize(3072); //block size of RSA
                        KeyPair rsaKeyPair = keyPairGen.generateKeyPair();

                        BigInteger cipher = RSA(data, rsaKeyPair.getPublic(), nPubBigInteger,e);

                        long rsaTimeEnd = System.nanoTime()-timeStart;

                        System.out.println("The RSA cipher time (nano second): " + String.valueOf(rsaTimeEnd) + " ---> (Milisecond) : " + String.valueOf(rsaTimeEnd/1000000));
                        System.out.println("Overhead of RSA compared to AES (nano second): " + String.valueOf(rsaTimeEnd-aesTimeEnd) + " ---> (Milisecond) : " + String.valueOf((rsaTimeEnd-aesTimeEnd)/1000000));


                    } catch (Exception ee) {
                        ee.printStackTrace();
                    }
                    break;


            default:
                break;
        }
      
        
    }

 
    public static BigInteger encrypt(String message, BigInteger n, BigInteger e_BigInteger) {
        byte[] bytes = message.getBytes();
        BigInteger plaintext = new BigInteger(bytes);
        BigInteger ciphertext = plaintext.modPow(e_BigInteger, n);
        return ciphertext;
    }



  
    private static String generateRandomPlaintext(int length) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";

        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(characters.length());
            char randomChar = characters.charAt(randomIndex);
            sb.append(randomChar);
        }

        return sb.toString();
    }
 
    public static BigInteger[] computeEC(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        } else {
            BigInteger[] getValue = computeEC(b, a.mod(b));
            BigInteger gcd = getValue[0];
            BigInteger x = getValue[2];
            BigInteger y = getValue[1].subtract(a.divide(b).multiply(getValue[2]));
            return new BigInteger[]{gcd, x, y};
        }
    }

        public static BigInteger RSA(byte[] data, java.security.PublicKey publicKey, BigInteger n, BigInteger e) {
            

            int blockSize = (3072 - 384) / 8; // 384 bits padding
            int dataSize = data.length;

            BigInteger ciphertext=BigInteger.ZERO;

            for (int i = 0; i < dataSize; i += blockSize) {
                int blockLength = Math.min(blockSize, dataSize - i);
                byte[] block = new byte[blockLength];
                System.arraycopy(data, i, block, 0, blockLength);

                BigInteger plaintext = new BigInteger(block);
                ciphertext = plaintext.modPow(e, n);                
            }

        return ciphertext;
    }

    private static byte[] AESEncrypt(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Generate random IV (Initialization Vector)
        byte[] iv = new byte[cipher.getBlockSize()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Encrypt the data in blocks
        byte[] encryptedBlocks = cipher.doFinal(data);

        // Prepend the IV to the encrypted data
        byte[] result = new byte[iv.length + encryptedBlocks.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedBlocks, 0, result, iv.length, encryptedBlocks.length);

        return result;
    }


}