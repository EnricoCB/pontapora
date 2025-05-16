package ifms.edu.pontapora.service;

import ifms.edu.pontapora.model.User;
import ifms.edu.pontapora.model.UserPrincipal;
import ifms.edu.pontapora.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username);
        if(user == null) {
            throw new UsernameNotFoundException(username);
        }
        return new UserPrincipal(user);
    }
}
