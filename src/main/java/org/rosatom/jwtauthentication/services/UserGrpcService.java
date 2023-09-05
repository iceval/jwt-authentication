package org.rosatom.jwtauthentication.services;

import com.google.protobuf.Empty;
import io.grpc.stub.StreamObserver;
import net.devh.boot.grpc.server.service.GrpcService;
import org.rosatom.jwtauthentication.User;
import org.rosatom.jwtauthentication.UserServiceGrpc;

@GrpcService
public class UserGrpcService extends UserServiceGrpc.UserServiceImplBase {
    @Override
    public void getUserInfo(Empty request, StreamObserver<User> responseObserver) {
        responseObserver.onNext(User.newBuilder().setName("NameUser").setSurname("SurnameUser").setAge(20).build());
        responseObserver.onCompleted();
    }
}