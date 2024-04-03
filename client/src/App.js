import React, { useEffect,useContext, useState} from "react";
import Header from "./components/Header";
import Login from "./components/Login";
import { Routes, Route,useNavigate } from "react-router-dom";
import Dashboard from "./components/Dashboard";
import Error from "./components/Error";
import PasswordReset from "./components/PasswordReset";
import ForgotPassword from "./components/ForgotPassword";
import Register from "./components/Register";
import CircularProgress from "@mui/material/CircularProgress";
import Box from "@mui/material/Box";
import {LoginContext} from "./components/ContextProvider/Context";

function App() {
  const [data,setData] = useState(false);
  const {logindata,setLoginData} = useContext(LoginContext)
    // console.log(logindata.ValidUserOne.mail);

    const history = useNavigate();
  const DashboardValid = async () => {
    let token = localStorage.getItem("usersdatatoken"); //doubt //we stored the token in localstorage...usersdatatoken which is create in login.js
    //console.log(token);

    const res = await fetch("/validuser", {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        Authorization: token,
      },
    });

    const data = await res.json();
    // console.log(data);
    if (data.status === 401 || !data) {
      console.log("user not valid");
    } else {
      console.log("user verify");
      setLoginData(data);
      history("/dash");
    }
  };

  useEffect(() => {
    setTimeout(()=>{
      DashboardValid();
      setData(true)
    },2000)

  }, [])

  return (
    <>
      {
        data ? (
          <>
            <Header />

            <Routes>
              <Route path="/" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/dash" element={<Dashboard />} />
              <Route path="/password-reset" element={<PasswordReset />} />
              <Route path="/forgotpassword/:id/:token" element={<ForgotPassword />} />
              <Route path="*" element={<Error />} />
            </Routes>
          </>

        ) : <Box sx={{ display: 'flex', justifyContent: "center", alignItems: "center", height: "100vh" }}>
          Loading... &nbsp;
          <CircularProgress />
        </Box>
      }


    </>
  );
}

export default App;