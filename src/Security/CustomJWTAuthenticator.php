<?php

namespace App\Security;

use Firebase\JWT\JWT;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class CustomJWTAuthenticator extends AbstractGuardAuthenticator
{
    private  $em;
    public function __construct(EntityManagerInterface $em)
    {
        $this->em = $em;
    }
    public function start(Request $request, ?AuthenticationException $authException = null)
    {
        $data = [
            'message' => 'Authentication Required'
        ];
        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED); 
    }
    public function supports(Request $request)
    {
        return $request->headers->has('X-AUTH-TOKEN');
    }
    public function getCredentials(Request $request)
    {
        return $request->headers->get('X-AUTH-TOKEN');
    }
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        try{
            $credentials = str_replace('Bearer ','',$credentials);
            $jwt = (array) JWT::decode(
                $credentials,
                $this->params->get('jwt_secret'),
                ['HS256']
            );
            return $this->em->getRepository(User::class)->findOneBy([
                'email' => $jwt['user'],
            ]);
        }catch (\Exception $exception){
            throw new AuthenticationException($exception->getMessage());
        }   
    }
    public function checkCredentials($credentials, UserInterface $user)
    {
        //return true;
    }
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
        return;
    }
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new JsonResponse([
            'message' => 'Anshul Jindal'//strtr($exception->getMessageKey(), $exception->getMessageData())
        ], Response::HTTP_UNAUTHORIZED);
    }
    public function supportsRememberMe()
    {
        return false;
    }
}