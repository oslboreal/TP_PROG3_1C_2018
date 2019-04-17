<?php

require_once '../models/User.php';
require_once '../controllers/autentificadorJWT.php';
require_once '../models/Table.php';

class Validaciones{
    public function validate_new_user($request,$response,$next){

        $body = $request->getParsedBody();

        $errors = array();
        $dataOk = array();
        
        $reg_user = "/^[a-zA-Z0-9\s]{1,50}+$/";
        
        // TODO: Usar los if inline.

        if ( !isset($body['full_name']) || !isset($body['user_name']) || !isset($body['password']) || !isset($body['role']) ) {
            $msj = array("ok" => "false", "msj" => "No se enviaron los campos requeridos");
            return $response->withJson($msj, 400);
        }

        $checkUsr = User::find_by_username($body['user_name']);

        if(count($checkUsr) > 0){
            $msj = array("ok" => "false", "msj" => "Ya existe el usuario.");
            return $response->withJson($msj, 400);
        }
        
        if(preg_match($reg_user,$body['user_name'])){
            
            array_push($dataOk,'user_name');
        }
        else{
            array_push($errors,'user_name');
        }

        if(strlen($body['password']) > 3) {
            array_push($dataOk,'password');
        }
        else{
            array_push($errors,'password');
        }

        if($body['role'] == 'SOCIO' || $body['role'] == 'MOZO' || $body['role'] == 'BARTENDER' || 
        $body['role'] == 'CERVECERO' || $body['role'] == 'COCINERO') {
            array_push($dataOk,'role');
        }
        else{
            array_push($errors,'role');
        }

        if(count($dataOk) != 3){
            $msj = array("ok" => "false", "err" => $errors);
            return $response->withJson($msj, 400);
        }

        return $next($request, $response);
        
    }

    public function checkMozo($request, $response, $next){
        $token = $request->getHeader('token')[0];

        try{
            AutentificadorJWT::VerificarToken($token);
        }
        catch( Exception $e ){
            $msj = array("ok" => "false", "msj" => "Fallo autenticación");
            return $response->withJson($msj, 403);
        }

        $data = AutentificadorJWT::ObtenerData($token);
    
        if($data->role == 'SOCIO' || $data->role == 'MOZO' ){
            $request = $request->withAttribute('user_id', $data->id);
            return $next($request, $response);
        }
        else{
            $msj = array("ok" => "false", "msj" => "Fallo autenticación");
            return $response->withJson($msj, 403);
        }

    }

    public function checkUser($request, $response, $next){
        $token = $request->getHeader('token')[0];
        
        try{
            AutentificadorJWT::VerificarToken($token);
        }
        catch( Exception $e ){
            $msj = array("ok" => "false", "msj" => "Fallo autenticación");
            return $response->withJson($msj, 403);
        }

        $data = AutentificadorJWT::ObtenerData($token);
        if($data->role == 'SOCIO' || $data->role == 'BARTENDER' || $data->role == 'CERVECERO'
        || $data->role == 'COCINERO' ){
            $request = $request->withAttribute('user_id', $data->id);
            $request = $request->withAttribute('role', $data->role);
            return $next($request, $response);
        }
        else{
            $msj = array("ok" => "false", "msj" => "Fallo autenticación");
            return $response->withJson($msj, 403);
        }
    }

    public function checkAdmin($request, $response, $next){
    
        $token = $request->getHeader('token')[0];
        
        try{
            AutentificadorJWT::VerificarToken($token);
        }
        catch( Exception $e ){
            $msj = array("ok" => "false", "msj" => "Fallo autenticación");
            return $response->withJson($msj, 403);
        }

        $data = AutentificadorJWT::ObtenerData($token);
        if($data->role == 'SOCIO'){
            $request = $request->withAttribute('user_id', $data->id);
            return $next($request, $response);
        }
        else{
            $msj = array("ok" => "false", "msj" => "Fallo autenticación");
            return $response->withJson($msj, 403);
        }
    }

    public function checkTable($request, $response, $next){
        $identifier = $request->getHeader('identifier')[0];

        $table = Table::find_by_identifier($identifier);

        if(count($table) == 0  ){
            $msj = array("ok" => "false", "msj" => "No existe la mesa");
            return $response->withJson($msj, 403);
        }

        return $next($request, $response);

    }
}

?>