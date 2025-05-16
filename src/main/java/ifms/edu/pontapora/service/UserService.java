package ifms.edu.pontapora.service;

import ifms.edu.pontapora.model.User;
import ifms.edu.pontapora.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;

    private final AuthenticationManager authenticationManager;

    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, AuthenticationManager authenticationManager, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    public User register(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }


    public String verify(User user) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword())
            );
            if (authentication.isAuthenticated()) {
                //TODO gerar token JWT
                return "Success";
            }
        } catch (Exception e) {
            //TODO lançar exceção
        }
        return "Fail";
    }


}
