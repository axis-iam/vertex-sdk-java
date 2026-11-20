package example;
import com.chaosguide.iam.vertex.web.TestIam;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.SpringApplication;
import java.net.URI;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
/** Exclusive controlled IAM plus a clean Maven app. No shared IAM or production data. */
public final class BffBrowserFixture {
    public static void main(String[] args) throws Exception {
        int port; try(ServerSocket socket=new ServerSocket(0)){port=socket.getLocalPort();}
        URI origin=URI.create("http://127.0.0.1:"+port);
        TestIam iam=new TestIam(); iam.mfa=true;
        SpringApplication app=new SpringApplication(BffApplication.class);
        app.setDefaultProperties(Map.ofEntries(Map.entry("server.port",Integer.toString(port)),Map.entry("server.address","127.0.0.1"),
                Map.entry("vertex.web.origin",origin.toString()),Map.entry("vertex.web.issuer",iam.config().issuer().toString()),
                Map.entry("vertex.web.audience","api"),Map.entry("vertex.web.client-id","web"),Map.entry("vertex.web.client-secret","fixture-secret"),
                Map.entry("vertex.web.development-loopback","true"),Map.entry("logging.level.root","WARN")));
        var context=app.run();
        Runtime.getRuntime().addShutdownHook(new Thread(()->{context.close();try{iam.close();}catch(IOException e){throw new IllegalStateException(e);}}));
        Files.writeString(Path.of(args[0]),new ObjectMapper().writeValueAsString(Map.of("origin",origin.toString(),"iam",iam.config().issuer().toString())));
        new CountDownLatch(1).await();
    }
}
