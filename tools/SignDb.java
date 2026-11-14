import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Assina a base de assinaturas do antivírus. Roda direto com o JDK, sem compilar:
 *
 *   java tools/SignDb.java keygen [arquivo-da-chave]
 *       Gera um par de chaves. A privada fica em keys/signing-private.key (ou no arquivo
 *       indicado; NUNCA suba para o Git). A pública aparece na tela: adicione em
 *       SIGNATURES_PUBLIC_KEYS no app/build.gradle.kts.
 *
 *   java tools/SignDb.java sign caminho/sha256.txt [arquivo-da-chave]
 *       Atualiza a linha "#version=" com a data/hora UTC atual e gera sha256.txt.sig.
 *       Suba os dois arquivos para a hospedagem estática.
 */
public class SignDb {

    private static final Path DEFAULT_KEY = Path.of("keys", "signing-private.key");

    public static void main(String[] args) throws Exception {
        if (args.length >= 1 && args[0].equals("keygen")) {
            keygen(args.length >= 2 ? Path.of(args[1]) : DEFAULT_KEY);
        } else if (args.length >= 2 && args[0].equals("sign")) {
            sign(Path.of(args[1]), args.length >= 3 ? Path.of(args[2]) : DEFAULT_KEY);
        } else {
            System.err.println("Uso: java tools/SignDb.java keygen [chave] | sign <arquivo> [chave]");
            System.exit(2);
        }
    }

    private static void keygen(Path privateKeyFile) throws Exception {
        if (Files.exists(privateKeyFile)) {
            System.err.println("Ja existe " + privateKeyFile + ". Apague manualmente se quiser mesmo trocar a chave");
            System.err.println("(o app so aceita as chaves publicas listadas em SIGNATURES_PUBLIC_KEYS).");
            System.exit(1);
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();

        if (privateKeyFile.getParent() != null) Files.createDirectories(privateKeyFile.getParent());
        Files.writeString(privateKeyFile, Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));

        System.out.println("Chave privada salva em " + privateKeyFile.toAbsolutePath());
        System.out.println("FACA BACKUP DELA em um lugar seguro. Se perder, nao da para atualizar a base.");
        System.out.println();
        System.out.println("Chave publica (adicione em SIGNATURES_PUBLIC_KEYS):");
        System.out.println(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
    }

    private static void sign(Path dbFile, Path privateKeyFile) throws Exception {
        if (!Files.exists(privateKeyFile)) {
            System.err.println("Chave privada nao encontrada em " + privateKeyFile + ". Rode 'keygen' primeiro.");
            System.exit(1);
        }
        byte[] keyBytes = Base64.getDecoder().decode(Files.readString(privateKeyFile).trim());
        PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

        String version = ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"));
        List<String> lines = new ArrayList<>();
        lines.add("#version=" + version);
        int entries = 0;
        for (String line : Files.readAllLines(dbFile, StandardCharsets.UTF_8)) {
            if (line.trim().startsWith("#version=")) continue;
            if (!line.isBlank() && !line.trim().startsWith("#")) entries++;
            lines.add(line);
        }
        byte[] data = (String.join("\n", lines) + "\n").getBytes(StandardCharsets.UTF_8);
        Files.write(dbFile, data);

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(key);
        signer.update(data);
        Path sigFile = dbFile.resolveSibling(dbFile.getFileName() + ".sig");
        Files.writeString(sigFile, Base64.getEncoder().encodeToString(signer.sign()) + "\n");

        System.out.println("Versao " + version + " com " + entries + " assinatura(s).");
        System.out.println("Gerados: " + dbFile + " e " + sigFile);
    }
}
