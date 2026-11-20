package example;
import com.chaosguide.iam.vertex.web.WebBffConfig;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import java.util.Map;
/** Example-only public browser configuration: no confidential credentials. */
@RestController
public class PublicWebConfiguration {
    private final WebBffConfig config;
    public PublicWebConfiguration(WebBffConfig config) { this.config=config; }
    @GetMapping("/web-config") public ResponseEntity<Map<String,String>> publicConfig() {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(Map.of("issuerUri",config.issuer().toString(),
                "clientId",config.clientId(),"redirectUri",config.origin()+"/"));
    }
}
