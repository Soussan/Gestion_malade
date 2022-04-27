package ma.emsi.patientsmvc.sec.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;
@Entity
@Data @NoArgsConstructor @AllArgsConstructor
public class AppUser {
    @Id
    private String userId;
    @Column(unique = true)
    private String username;
    private String password;
    private boolean active;
    @ManyToMany(fetch = FetchType.EAGER) // Lazy cad à charque fois on charge un user de la bdd hibernate ne va pas charger automatiquement les role de cettes user au mémoire son contraire est le mode Eager
    private List<AppRole> appRoles=new ArrayList<>();
}
