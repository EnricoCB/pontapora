package ifms.edu.pontapora.controller;

import ifms.edu.pontapora.dto.LoginRequest;
import ifms.edu.pontapora.model.User;
import ifms.edu.pontapora.service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public User register(@RequestBody LoginRequest loginRequest) {
        User user = new User(loginRequest.email(), loginRequest.password());
        return userService.register(user);
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest loginRequest) {
        User user = new User(loginRequest.email(), loginRequest.password());
        return userService.verify(user);
    }


}
