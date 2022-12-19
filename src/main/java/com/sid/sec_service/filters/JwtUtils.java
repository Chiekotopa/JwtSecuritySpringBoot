/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.sid.sec_service.filters;

/**
 *
 * @author CTC
 */
public class JwtUtils {

    public static final String SECRET = "mySecret1234";
    public static final String AUT_HEADER = "Authorization";
    public static final String PREFIX = "Bearer ";

    public static final long EXPIRE_ACCESS_TOKEN = 2 * 60 * 6000;
    public static final long EXPIRE_REFRESH_TOKEN = 15 * 60 * 6000;

}
