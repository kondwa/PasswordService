import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

class PasswordService{
    private static SecureRandom random = new SecureRandom();
    public static String generateSalt() {
        final byte[] salt = new byte[22];
        random.nextBytes(salt);
        return new String(Base64.getEncoder().encode(salt));
    }
    
    public static String hashPassword(final String salt, final String password) throws Exception {

        // Assert.hasLength(salt, "Salt is not allowed to be null or empty.");
        // Assert.hasLength(password, "Password is not allowed to be null empty.");

        if (salt.length() < 32) {
            throw new IllegalArgumentException("Salt must have a minimum size of 32");
        }

        final StringBuffer hexString = new StringBuffer();

        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");

            final String text = salt + password;
            final byte[] digest = md.digest(text.getBytes("UTF-8"));

            for (final byte element : digest) {
                final String hex = Integer.toHexString(0xff & element);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

        } catch (final Exception e) {

            throw new Exception("Hashing Password failed.", e.getCause());
        }

        return hexString.toString();
    }
    
    public static void main(String[] args) throws Exception {
        System.out.println("Password: ");
        String password = System.console().readLine();
        String salt = PasswordService.generateSalt();
        String passwordhash = PasswordService.hashPassword(salt, password);
        System.out.println("The Password: "+password);
        System.out.println("The Salt: "+salt);
        System.out.println("The Password Hash: "+passwordhash);
    }
}

