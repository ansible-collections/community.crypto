# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Felix Fontein <felix@fontein.de>

from __future__ import annotations

import base64
import binascii
import datetime
import typing as t
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, types
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_pem_private_key
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, CertificatePoliciesOID, AuthorityInformationAccessOID, ExtensionOID


# To regenerate a private key, simply remove the corresponding line and run `nox -Re create-certificates`.
# It will print the parts to copy'n'paste into here.
private_keys: dict[str, str] = {
    'bazbam_root': b'09PT09O8u7m3sN6srb/erqy3qL+qu961u6fT09PT0/Szt7e7kYm3vL+/tb2/r7u/is62n5DKrKa/hJedrZnIj8iHp62Hs5+RtMaylZeki4+4u8m5rpvNiZyruLWpioqR9InIkqaxhp24jMjRjc7Kx82pu5uIuLi0kI+KrtXLn42pl421zqrPqJG4qs2Gncufz7u5z7WVrMabvbO8n5PVss30rMenh7SOt4aXu621v6SwrrSqy7iVjp2ot7aal4mtx5KXv7bNx7aclLzPhrGyzMa1vKvVv5uMmqmRyYaQp7rKzPTPrJuTvKnVs82Ujsqxzri3iciVuJzGkc2Mi5iul5fHusy0rYfRvJKGhLXKsdGXvY60iaqPia6MiListpGWmK229LbJzMuutbDNrafIlLSktcq8i4ycsoyuhqa3uJ+xvciks4i4zs2SlqyzhInVmrattY+yl7a/s87Hl46EsI6fp5r0kbqYtpOdtrutt7jGusuTkJ+zz73VrL2rjZads7mkubHOyMu1iIm3ur+vv7y/kbe8v73Oi5mopJvJt86viZmYt/SvmNWUyaa5i9Wuj7uOtL+/zYaZsY/RprPMlb/PkIzPhMuJj7mUxpWEhJurp9GzhKuquI6OkZayl5KVl6TL0ZbG9Lq8h9W7trWpzZmXsY2GxrWZh8zRjrmUrq+qjoy3k4injcuMzpaQhKe/kI6rqciRhIank4y0jb+qk8eunKnM0bz0zZ2Xv5HJ1au1upK9qY2GybiYx5Kzt5Gvx5zPxqSqkpm6vYTLp5qQkImox6aMqo66ttWbypS0m8mrmsiVmo+blvS2sYSNncyckJO3k6bHx7CIrbW7u7iYloezlqes1cq3r7WUi7KEsabGytWakKm6jbaVsMyvl72ZuZu3rpudi7/R9Ka7tcian4bLsIjOicfKnbHJlrOIsq+KnNGPlJ2dkbDImMe8pK3PjIettqS8x8uW1bKaqLi0mIrRl5mHipWWqsr0ypKmp6qTu72Zp7u/zI6TycfRlKyYyYiXs6mnlYrOmKSTv5mRsbSoz7qYr4SpzauNx5aJkKuylceGi8+dx6ucsPSniJyQnYvVjpe4qMacn4iKiLWom8uakJian4zKuZO5vZ2xkMyJu5LNpq2Zn7eUycmTuZOky5+SqY+Mkou1y4TM9LDVk62tpLPOjambk8a7jbmRv5Oxtqiop5bJ0Yisypixr7GHyJOJsczImoufmLKrja66iIuIqpW9mae7v8+OiZD0k7eEkI6rqrG1hJKqxpWQmJDLsbTMy6vLm6eHyoiZkLKRkJrGnJadz5eQmZeLu7mx1bLPipCLlcewq9GH0Y2xjvS2kay0ionVprfLz8+Una/Lj5+Gy6uTxpa/tZG1hpHNkLWIpo+7iI+mzovOkpSwy7OWkoTMmdGHmpyrj5qaya7M9Mmtz6yxh42Wn6usmI+Pna2JraSJqJ28ysyNnJC6ubGbi7+Nq67Jnb2Zp7+IzrSfhMjGtoimn46Wr52ombKfv5T0h7+ExrXNhJ+5yrONrYaRqJSGhIuku6SS0cnHkZeGxpyLp66Ji6+SirbJzb2JzIusyIrKh72OuseqrrCwzJuGsPSsudGyj6enjqeExo20tpeSyoqKmobGm7uxk7uSi4mtu6+4iKm1lq60lpS5qYrVtIm5r5yEz6SRh4jOtqeatKuW9M65p6uHvb/Nq7GXm4a3p4Sbj4e9h6+1vJmvvZvVq9WIlpCVzL2wusammomdmsm1j5jHzsq8jbCMlZrPjbuz1b30h4enk6mGqoSusZSUsYqrr8+Hk4THtYfHj7qPkpK/qp2zqobPzKSLkcjOr5muibS61ayOj7+sypunipipk8+SjvSUkMmolJW3preVj6iQlI6MjZ2w1Y6/iorKqsmXpLq00beuk4ecmrmEtcbN1bmvs5mWhIiWk5q7jY6Il62tms+t9LuZjIvKibW8mb+rq6SOprfLv6aUnb+bsburp4mbl4q9uJGrhInI1Ziv1YTVv42QsZqmn4yQvYySjraRkaaaya/0ibvNxp2Ohp+KlIyRmbuqt8mUlY6oh4utuaSxrJuQidHJyZmftZTKv9XVp5qWubyuvJ+7nauLqr+7qKjIzYu5lvSqqM2WtbHRuKuPq6mkyM/Nip2vkpSturmdjpqEp5+70ZqEzIuMlqqftcmHrrHOlMqSt7SU9NPT09PTu7C63qytv96urLeov6q73rW7p9PT09PT9A==',  # noqa: E501
    'cert1': b'09PT09O8u7m3sN67vd6urLeov6q73rW7p9PT09PT9LO2nb2/r7u7t7eHiY+fqoSapIbNjcfPq62pk82wupOml5CXz6/JqNWKmZ3Pp4aO0aeQl52Rv5G5vb2Pua2zysf0v4m7tpGrr7qvmb+71YiOmZmIu4i1hJem1aSHt5POmLGr1cubrIaZu4bLzL+P0aa9s4+cic+ErZmYiJStz6bNp/Stk5+0s66xyaSPzLipvJmLh62Un6S9iM6Mnaycy668tr+/w8P009PT09O7sLreu73erqy3qL+qu961u6fT09PT0/Q=',  # noqa: E501
    'cert2': b'09PT09O8u7m3sN6srb/erqy3qL+qu961u6fT09PT0/Szt7e7jr+3vL+/tb2/r7u/krq3zaSImruMjLCEyo+2lM2qkY+GkMbGkJSct5SQn4vHy52SyYSpj8+2vNWrqc7L9I6ahsaVsM2rupe8y7PIq8eLtYq6uLWal7mZlaTJyZCWtIuHiIqbp4q6i6aRuJGth7aKvaapjq/OirjRvZ+MqZX0u6m2tsi7q9GPvayMyKSbr5PVzJeMs7avzY2UjZqQzrSpncuchJyaubS0i62vmZKVsKSKsMuakp2Qsb2Pibecu/SzhJ3VjaeQrNWnu8bNvcuasrXJiMzRmpzHqbPLtcaPmb+xuJmRrq28tZeJsa7Oz4/Glba6sY2wp8/Gyra7zcfG9MqOvZbRzJKTurbKqs6ujIu0rLm6qI6LmKTNu5Wmi4nGqpaKuL+ku4ewzb2SkpzLtKyLlayOk7i71ZWsmsm6jJ30q5WUkJHMvM+IqsnOkqS3pJHLrLm2vcaYrYqdp7G0pJmfzY+0qom3ur+vv7y/kbe8v72ch7jNjcqHkqrJuJbLm/S5h4zHn6ikkL/Gv86azY6GubuvyMekyo+Gqc7OyYnPjraYlraItpfLic6L0baIjb2SiJSdu6q2hqiHm4udj7jG9JmuypmIyr2ms7+Rz6/OiNGMqYi0isiEzbHVyKa0x5OGrbTRu4efiobNzIi0iJHLrMukv7vKtqTOsq6drp+3zoj0va67rtWqtKrOionMv5ScqZSIy7qWqrfHnbuWsJG7x5ewtZGYt6SGubqXvNW3lpPPqMnHi6fLsomLzbeNh9XNt/Szkqqcic2SlLCQioetqqS9lruE1ayktMuxy73RsZuGkIeoi46QvbjHtbyNmYSVp66xpLakvbW/zpOvrri3nLaO9MnLusa4prKTmYiVho+pq5HNubS/rNGarbKvr5aSjYqTy4a5x822lqics6SUkY3OnJiuhIqnrJC9tqmXjNWGi7T0y5bRkomLu72Zp7u/ibydtIebsYyWya3Imbyyl5ykxrnGjbq6irS3pqq0pJGkm7KIqKu6yKaQmom8j5icsK+/kPSPkJiYlbmwzMnMrIaIzrnHhKqJqrWnlsbPkbWLlImdnLuLvLqLlauatam7zpq5pKyLyairmonGk6+ks63GlrKO9Lm/u5qss83JjbSknLbJvZ+TmZWGs7+wypOuy8mwhK+q0ZqPp4mNmZWfkLKSsKvJzLivlpmdiLu9mae7v4anvab0u72YnYmfmp3OqJOSz7C9iJLMjISntoSSx7eNs7TJv6yIt9WLiZSNu6uJhM6qyZiZtZCcirGZtKfMlKi6spfHt/SJm6jRk6myhqmSp5qVvLTHy66StKmEhpidyJiszI+7hsyRza7Gtqe4z5GYpLy3zpGHh6/Lr6yQhouav6eSm6ST9IqNmp2MjLy4i5q4l7yfsLmVzJ2Eyrissaevm7OsxpWOz5+Nl6+6xr2Zp7/Kss6qlY2oiMeRt6eZn5upl4S1zcj0k6ySkrmRkbe7xrSynYqRibS3pKnPqp+5tceXy7eLms2uv7XRsNWXq86KiqmkjbPVp6e6z6jR1YSLjouptb2Ej/S7yr2czZaosZmXlamSjYzNqqnPxrGnlZO9iNWHkbeamKyJiY6VsJHIpM2/qITHu6eSiLnPtZDI1Yurl7HVv7Gr9MnJlqfMsrGpu4fGjoynrp/Mr8+Vxq+1vJmvur+cl9G8nNGojq+kpojJupySvaeajbOPjsiJkJ+qs8nHm7vRuqv0uJi1l7u6j7+fs5S0i8+8r6rLi7aIyMyLiJu0xsvPlYuZko3Mj5vIn5HRlZrNs5+0vbi0i8a2zae8vKvPiKeruvSbiq3PpMyUxonPsYapp9HJlKeThKeRtpa4z8rG0c6mkY63kYyzkpaaqZeyz5rOpKmcubiWuYmwnL2PzJKfx4fO9Ma3yZGOr7W8ma+9zJ2oyZfGkIebh7CYuMa4qaSYhqiuvK+PiJOkl7Ovsb2/zKvVjJe8l6SHp4SPiZSssMfVjZf0jZm1mpfRv7zOlKmEj7qVs7OtsofPi6exvJyJi52GkK+zy6ukl42Sp4y1upGWsMe5mJGSpLCJv7W6lIavlbiVyPTPkJy3isvOmdXPn42vnMqmkb+2rY3IppCXnZOLkqa8m6rKtqrJj8yxypOzua2Ilr+yx7+5lonDw/TT09PT07uwut6srb/erqy3qL+qu961u6fT09PT0/Q=',  # noqa: E501
    'foobar': b'09PT09O8u7m3sN6srb/erqy3qL+qu961u6fT09PT0/Szt7e7kZm3vL+/tb2/r7u/jYa8rZONjJKwyLXJkZWTrNGthMbIuZHIzriZh5O7qq6xsomEkKnOjc2f0cymqr+y9L3PmKiGzZOYs7iRqL/Lu6ycrY6QtZDOnaiRiLGWh8iKvLKtsKqyx5uRq5TLkre0u6umzsmdp8qUl9Gvy62ayo70yJqEq6rVn4yxvJqPjpONtL29ps3IzbmqncyUyse0s5G2zaaTyYrMrLmNz82uqLSclYmpjqSVk7qkl6aTyrqkuvTKyreHtIm1z7aGlp2Nmcavmc67q4iczbymlq29uJu8x72czJeyx4qrhq6WrqjKuIu7jJHVtp+VhpSfkry4rJKn9Jytlq6QsrmGsJyUspK3i82JsrCWr5SauayvhIeoza26k4+khse/sIiLtLyOlLqIrrLIy5Cpq66Oyciou7e0ic70jMqZusedmZqWnJu9tY3JuZnKnamSy4uvxqqnz6ydzauqnMi5uq+3ur+vv7y/kbe8v7ywkpCJu5m2mKqOtI+Xz/SUmb+Lsp+krZSkqomQsZbOsZyKq6adpseRx5Sxza22j5O1sYqPx8/GtpmxjJOT1ZWLr820lriIjY+WsInVrJGk9LOJjqSNpM2/x7qvuMeLz7+NuoaZlcnKlrqKp869lJOQmLesqbiwrZTGsbHMqciQhMydjpqct83Rp8y6l8zVnbf0mYqmkJC2vdG0rMaspM6LttGOzdWss7GKupCvqs7GzI66vJe5kaur1Y/IrNXMsNWUr6uGvaqXh8upyLS/ipKptfSqrJmKqM3Nm9GOqZyPsobMqKaGpJa0p8unj7m5t6a7n5aTuo3OqYbR1bDRvI7Hn4+tkKyXspm2nJKfkpDVmcuf9LqSlaq4yY2cyqbNkJeqv8+xzJanjq25pr2IyKqaps6GhreSqpSdj8qkq5u1iYe/jNWvho2Q1YbGz6SM0ZyPuLH0y5CH1YnLlb2Zp7u/xr2H0cuzm7y8ibqoktWotrSIy7POiLWts8upho6Rppi/mre2rrKHpLGJl6mnu7y61ZnVjfS/zs6MrJSKiYzIta3Hss+o1YvHktWZqZi4i8yOm5jVuJGtqL2myr+cq5ySlM2EtZeayMePlc+Tv820vKmMk7iG9JGG1c6JuamSn5PLx7K8pIy2j6fIlsm4kpOKlbOUt9XIs5qHmcevua6Oi5zKx5HVtc2qirGWtKu9mae7v4iKhLz0jc24vYupnJSkiI2cy824z7ewuq2sk7Way4y1qMemsa6dib2Jtoivssqbx7aHm5qdm62ql7eTuNXVyZzKmcqkvPSvtpyHuMiQqsrJh5qxismSi7i0pouq1cjRrbOZrb3HybOR0batrourms7JhNGGlsfVr8+Jj6yskcyyn7Sqroy59JObqKfGjbW3zomSjouNrJyruL+1ipvJyIaYqM2QsI3KzZqGp8uklb2Zp7zMyrvHl4rNrZiLs67RzLCnjcayqY70i8m1ipGficiSmYakpLi4xou3qrabqY+VzamOttGqpq+Kt7DOzpyMk87RjavHvJDKl7u2nKq1lNGLlZ+Tr5qVjfSayY+JmpW3rqfOk6yVmZaVp6+UtK+ZprO0mc6WpI3Nsaydq8mcpKy/pMaIv8u00buQmqSblMyTrL2okoeJqpWs9I2ulpe6tLa6irSztIaLn5uKmpGksa+1vJm6tcbKs5KWtreQt8mUyZ24lZSPmZOfnc21kqinmb23uqy4pLqssKb0pKaOz72Zi5jNkZuIx8qau8uwvZ/HkKqmyK2HmoyZxrq6xobMk4aKy52OjLTOk4uEl7yOyse1yL2YmIaHlYrVp/S4qq+EkK7Kh5mxyKSWlLG70a2vqJaLtriatci/t9GbpKaOtsinr7uOvaa8n8mPsJK/x66Sk52Xh66Q0cyqh7nJ9JbVy6y/kbm/qrKVsr+KrbCPzr22lKSqq5qxq62yt7PVm5a70ceV0auknKnJnJSIl7q1qsrRkrGUn46MqKm8i630u7u5soeJi5uLpJa3kcrPvcvOiaeIz66xirStiIaxqJiPtMuXrYe8ybWa1c+RtbKnjbrOiLeTmLK6iY/LppS2p/THtLGojqu6jsnMuYi6y4mZvLG7h83Lu4Swhq6ousqdldXOkpuRva3PpJKYrai7jLOJzonD9NPT09PTu7C63qytv96urLeov6q73rW7p9PT09PT9A==',  # noqa: E501
    'foobar_ecc': b'09PT09O8u7m3sN67vd6urLeov6q73rW7p9PT09PT9LO3uZW/mbu8vLq6yMeop4yVt6i2koq2i52qzorPx4eolM/Vz6uvrLDLtpqLvM+HlZCHv5HIsseUpKqUmMrNrIn0hqi5kpKOvMiNq4uZvImnuLXKu7u/vbWWpL+wl7+/rayfurG9iJHKq5euj5O/kbyuvZ2yysiwppGYqoyZpKyqhPSmi5yU0bSqiIqbh5OGi5anyp2fiaqXtou6prDLlqaripu3n8q/u46pmriRlbPGrYmPm66ZiLvPrIqYjZuLj47R9JKRy7uTl8i3zoSMp4aRn6S1h7C3rrGzpKSQq7PKucbD9NPT09PTu7C63ru93q6st6i/qrvetbun09PT09P0',  # noqa: E501
    'foobar_ecc_inter': b'09PT09O8u7m3sN67vd6urLeov6q73rW7p9PT09PT9LO2nb2/r7u7t7/IpKyam8eGsp+ZmbOHh4zRi5O70YeWmoefiI+tlMmur8mdutXJkqyPkqqRv5G5vb2Pua2zysf0v4m7tpGrr7qvmb+7i5Wayr3MmYnKms+zqrSTvZO9h42xl5G/zLO/rITKppunq7qXtb3Gv6i/jZvOnMmPmpCHz/STtcqcldW/q4q5tcy3qYi9urS5lbGsrIuTl4mQiZuSub+Jw8P009PT09O7sLreu73erqy3qL+qu961u6fT09PT0/Q=',  # noqa: E501
    'foobar_rsa': b'09PT09O8u7m3sN6srb/erqy3qL+qu961u6fT09PT0/Szt7e0tb+3vL+/tb2/mbu/kpKJlZPNssuQzrG7jJ+Y1Zm9qZupsKyYlKnIs6SfqbCRsaSLt5Onyqy8jKS5k5e19Ka5ucySrJOrkqqShKbMkZCkq7uIssfGv5+Xrbizh6+LrMepl7u2xquMiJ+0rryxp6iNvJqTsr2Oi6a5tIaOrpH0r4eSyMjPlZ2trseuuM2azJ2Su7OtybenkZqkib/LyZiZsqTOuay6iqankKjIrbmUr4uvyq2VnLuRnM6M0amVrfSbjKaql66cp7+npIzRmM2HkMmPqY2dmaSGnbuHzb+IrY7Rx73Jz4qQlMyXsY+Y1YqUiYamtZOHmsiN0c/Hy7ab9K2JyqetkbKskZ3RlLiOts7JmaSms7vOlqSytMyvtci6j5mKzbiM0ZWYtbq8qMmUkJTIramNmJWIyKSLk5GTjqv0lK6oj7bPs8qKhJu/kam1uajHjcqLk6+kzMuOqYSSiLeEnciYqZCbyLK5tb+VmIe6kbCah63Vt8uvvJG2xpDHlvSLt8e2lqyoy82zj4Su0ZGxvJWQjY6Np4mGs4rNvam8uqnN1bCuk86GjLCThLTKjs2wubaotpaEmJ+WpLTNu8iz9I7Lic2uk7LK1a+rsLOyrJyRuaawlbq9hLfNyY3PkZSWt7i/n5iQz5KZyYyalYeHtpC1p5G8vcmftrqrt7zNuMb0rKyWkKzPtImUiry7s4+U0bC5vKTLq5iRho2Is4eOtZ2QkqSckbmmx7S8tp+0mruyq9GElbWrqZfPrcvVrM2XtPTKm5aJvYyqhMqfnLObmp+akMyY1cqZyMnKs46njo+/va6Eus280dXIkJu4rI2Xk4rHj5+6j5iPzMuujNGtm7Wb9IuwtI3OrrK3ipjPj6eKqMmor5Cuq5+Py5HVq7LV1by7kp2xsKzLj5O6hpyrvMuNhqTVlaqruK6UhLzOvb+Ju7/0v6+1vb+Zv6aapsmdjpjIm6/Lk72Jjr+OlLqqx6SuzqaZi6qHiYifj8qxlKu/h7q1sMyRltGfm7+MuJGWroe4yvSbjbOLp4q9s42Mrpy/h8nGp7e8sozPhoq0jMiQqJSGh8rHt5yWk8aWs5qZkZbN1ZSXuoami722kIm1r7jJloa79JHPlL2MypitpL2qtseOhoSxy7XOnJuZiLnGlqaosKa6zc6Oy5OWyYiJxsyRma+JrYq/t6m/kIvKk83RtZmdurb0z723jLGfurG2rs/Rx6iSp72Vuam0qMqql5iczJnOiq+9y8abkrDIsarRzKiW1Zy2l66tzKu0spi3scmmraqIsPSGurW0vJi1hsu4kp24ioecyJO/n4So1bKbzpbOrYS3jsrInJOLmpOYvI/Nmaq1uam7v4iflarLjs7Ihpm/s4zJ9JmIrKiLpI7Vr7SEu7LRrsbMu7WNy6SzpM6s0cuchLLKi7amncanrYezvKeZlrKRr4Sfp6+Oy8aUn8yyjorPhKj0y5CmhtXOhomEsYunlpqfjZeVpKmszJfPk5aHqb27sYu9vIaNrM+6t4ixmMaWqa+rhKiRiMaMxr2Nj7ivhNGGy/STqMifpKadz7SGnK3Rp42Ny8epzrW2l5KRmMaEpL2MroqLhM+Oub3Mz8aHyKrGnZKWu8e0vae7yp2dj6e5ps/V9LLM1cuxvK/OsrfNlrnKtK2GsbKQiZeYmNHL1ZKOm821ubOoy4ewsMudiMyah43Ph7y2msvRuLPRqJCbkaaak470ur3LppGRp8iPj4qvl4iEy6StnK6pqL2KvJyWjcq4vbasuMmxzauVqqmmsJCMm7eWjZ26m4+6ioemp52IyMqNjPSutauqy4rJuJurnZaWkruIlZi6iLLNyZG6h5mJj6mWxrOtm5OHury3yLCSh4rLxs+Qr7W9v6+7v4m4v42Kuaqd9ImqrNWsv7uJtqast7+amo6wh9WMzIqHmJS/rsfVhJa7n8vKsJOxub/JqL2Ux5mbk7qwk62fn8jRssqalc65uMf0n6Sah7nKsJqOj7C8ys+uirLPr4m8tLq30auptobGk867jKivla6ryJG9r4+xqZeMp6eQi4inyrebl7HGxpHKs/SEm7aEuqiqiLjKmYisk7jPpoScuYiRx7u1monPmaiap8iZyrqcx5KpjY2Es5+Rkbuqt5iQt7Woz4yGnLm4s4uK9Iepna2UlKe8k4/JzpqxmKuEkoSqssedpISazorPjqSaip29i73Ipq+quMm5sJG3qpKmv8+Qio+/rcayrsiblo/0vM+curCRq7qdv5mqt6uEta+XvIq/kLqknIqslpG3rrG8z4iqjq+0t8fKxr/Ln52HjtW1mc2TlIuQib+5iqS2z/TKic/PjqiMrbi0jozVibW9v6+7v4e9mrayt821sZKayIeshKzKy5OmkY+os4ubrJHJqsqru4zHjMixqb+Py5mE9MadupmJjp+9hJyxjZKLk62Xrqi/ndW8zrqSz4eavLa8m4Svks7My4ScuauUjc/OqIyKqM2kt6ycz5SLsamJy5j0jZDJsLi0x4iGrJ+9u8vNp7PPv8yXrJWszca6sLCJypeUybSRt7+ozoastqe4u62mxr2TxrmUua7GtZGptqrIkvTHypK/hInJhIqJq7uSj5bInIvNlayklau9kZLPh86prqa9vJmNsIzKl6aMp5CQjpa7i5uXjLGdnbG5u6rOnYTM9MaVjbuLyo6IlpafvJ+nxqSZkpGQh86sn7SUjpyczLi5qZbLjLGuyoerncaWqJaqiqyVjYepycu2y5SZrs20kcj0v8+4kaTMsLiJma+VtYvVuZyRs6/Ns6Svjq/Vh5yJmZ+krIaqr5uMq4aJtb2/r7u/j6iPhqvLnIfHu8/MzL+RzfSGm5aKiq6Si5KnsY2VkYyGu6eN1Z2fkJOqi7Ocz7uypJLIs7S7tLC8iJKrkKfPiKeEz7uMuqaPnYbKhIiSjs669IyNlp2zt6aP0bjRktGrx7avv4+Q0bDHyJyms4mks52Y0ZG8yJWOzbqwjs6tuZuSkLHJv6a0zcm9mpqZvJmIxrj0kZS0h5rOmrzLlIa4kIi8jrCmmK6JkImfsMeKjqmplbWLqb+HjMiLkrzKr4eQt6/KxsuGpJeoh5GtrLvOiK6Tv/Ssl5S4yNW4iZiwyoiLvKyEl8fVyr2GzaiQlabOiIaNlrWx0aS5ys+2u8mpvMaNncycmbvJi6zRso7NqqaflMix9JipzrHGyJ3Hv5eXiseOqLOorKS/mouNyaiHzJqmiqjLqpK9kJO0qcuIqr2wsdXGj7nVlafRzbSIuMiUz4yVzpb0nJyolKmJtb2/r7+SkY6rq5m0lLPRpK7HyIuWmZqRkM2Nu7CzuK62rMqVuJu/rKSTqKaVjK2KrLyTmKaOr7GQpPSXmKSXyZmOyIy6jIaqiImUlc+Xjru3k5W/0Y3Oz6mUkY2a0aqRh6eQk7Omy6Skpoy3ypOG0c2yjrmVrYiRiZ2b9LCvhr2fma3OtaiRtoTMkM3Vxqafk8+ysam7j6zGiq2GuKSUm4iNs5i9kZCIuIi9jc2syLSnhKiyy6uZuKSGmqn0l8i/v6+91cepmZjLsZTLz5uzuJGak4SKnYzOnI69upKRscm3pJqtt9G2jYiynZPPjrqwp8yzrMicsp/KubG9x/SZjdGrjLnIjZiJz7WZuL3RsqmIhseRqbnRkMe7zK3Hpr21yLS8vZaompO8vYqYprS9qrGfqLaTl7i8qZmVhsaq9IeEk7CGqpGLzcq/z7OHlbfOtpC0iLGSrI7HuqrJqp2qv5G3vL+/yL+stofHpLOohry7zreq1ZCsl8/Mzae/s8j0n5HOjsbHkpTNk7Ko0cqci6ykrITOtJarmZmHzMm3yMubq4ebzLitpNHKkaebuayfj5DHirGdrZrNlqiIjJSwq/S90bmqrZmLs7OEk5uJyY6qj6fPjcrGr5OQspywzK2kiY+Jupewxp+zxriMmb/Lz8+pppuplIqsqYeUi7CcuYmr9IrLjtHLpNWInLSUm5O4x66LpNWVqcfVupioqtGHjJS7zJGEtYu4t5WahpmqrJqwv8zMzaiUrq/IurWsmc+Up7H0hoqrjLOYjoy2ls/Nrai1vYyyqpWbm5+7vamfsZzNx7CrhJqcz5SXmJ/Jjs6ZzbjJsY+p1YTPxpjMtKSajLqpmvTLt5KYy4eyuqSqxojLrauqu7HOnLaLhpLInNGMh6vKr5jVi5+JzrSrt7a71arVm8u9yLKnjNHIybuKxsP009PT09O7sLrerK2/3q6st6i/qrvetbun09PT09P0',  # noqa: E501
    'foobazbam_inter_bazbam': b'09PT09O8u7m3sN6srb/erqy3qL+qu961u6fT09PT0/Szt7e7jr+3vL+/tb2/r7u/k7HLz6e7yabKhr281YunjqvJzbOqj6nOlMyqj42TiKudjISIzbSE1czRn6Sarr+s9LemmKydt5Oqlq6smJGnj42Ns8amqZCxjIS7sY7Jx62qmbyzlM/HnaTGrru6uKa9l6edr7iSvJikjtGVlbqSh4r0r5yVr5LOu5TMtZmztpW1x9GszcvNmsao0c+HjMvNjLWwlKjGu5WGm7+xpJCmqaTPy5K9x5LRlcnKrrGYibuslPSRsqaazKqkrpyGyrPKpp+8nKS4mJeOyZKvkImVrsq9x4SruY62mMm5qb+ml8rViZLPtrikhIq6lK6djZHMm5qf9Lq9rMqsp4eKqaiJkLLIjZXIuraUz5GxhNW1qMvRic+EkbHRq4ymso61jaeNsbKJjZnHl6SMhs6MuLu4i7ecurT0y4SZlc/Rk6iTprqVibPVlZvIh4um1a+wqs6fu6+km8eorLeJh6+3ur+vv7y/kbe8v7+tstGQvJK4yaunupnPu/S2y7iLq7XGycmvupmfjIiJrZ2Ry5awp5LOjYjVn5Ctp7m1tLWTl8a9yr28hqikvbKbza6Nqri6hI62qM2Jyo2L9KeVy7W/zKyzxrmZvNWTkNWsncyMq4q7l82TqLeTkbSrhJnRkYytyp+7qrC4qMaMlZe8j7fHvMeatqzNrLyJkpX0qLKuu8uStofHu8i0l4evhK+XlZqpuczMh42SzMyv0ZmSuse6krqkjZSPqpOMn7Sfvbqnx4yKi4e2kpiQmY2wv/TH1Y2aprO/p7fIh5zK0bvNjKSHs469rdHIprqvzom6ssmWnbmGsdWWy8uUpM2ahoeKvM7PtpWOmLqkmZuXkIq29KmSrbSyh72vub2IkayyiL/Mua7LuZu/jMuurK2Su8an1aeOycfLxqSutcu7zLGxn8jMl7GMkrudjrXMmouxjdH0zJ+PhMmdlb2Zp7u/iJycu7eHhqqWkom8uLDL0ce1sc+Prpi/sqfVvJ/Py5vKyLKny5q0qrSLzIydudWWm9HIufSvrp2Si5yVn5vMnauyiZmVhqmbiqmnq7mql5GdmY6Sj6a2j4ypyaSmxpWzjLaIlLfVjq+RtLfGyp3KuYqwjMfM9Ii8kqezyI2mlMqajouTirCRtJSox5uwu8i5l4jV1Zi2iIjJk5e2m5GcpqSKyLXOpKnLitGZj869mae7v4SSzJf0t5qEjbmkis6Eh5GOmLPVlsumxsuVsYiuysictr2JkJuEmYS6qqzMm7O7h4bMtqSKzaaRl7CKhsbLkZ2ZkZyns/S9m5amzIaOtoSfqpGymJSOhLSux5jHk62Nh42at7u7qK2Nvb2Q1YSLsZmzjLeJ1a+yqMuPqbSvismuj42Pvb2U9JKXk6empqrOrcq5moiTjKqozKSyiofMjZXMqYSMhJPG0YfKyJaZzr2Zp7u/jNGfxorVxpuqnZHIl46urM+trZj0lcyXiYSwubiama+UsaqMsoupncm6h5LPq5+pt9HGhqjPvMqRz7KQzMathIzOtdGfv8yLkpGGk8iYkJufzLyIn/SskYyosL+EsazRi8m2uL+YmZevzZXIkojJx42/iabKpp25tbiO1cmHiLezn7OIkJe4yI+yu5SmtIyosZWQy8aa9J/Mx52YkZOptLmTjJeWica20ZzJyc6rvZmnu7+Whpa5y5C3icqdn5e2k5erlpXVtYafk6nJi5qZhJ28uJrPqMn0z6iRtpK2lciztKSrj42au4iJsa+puZikt7qq0Yeyz5yYlKqMtIqryJmVpJqatLO0ic+0h6iQjbyUqZq8vIiazvSqx8udy6+y0bSozpSOrc6JupCwspCqmrO0qbeOuc+Kn5C8mafPnMyok8asyZKNmo+5q7eIm66Wm5S0scaRt8uV9IeRhJbLrKu9mae/ypLItanRlbqZqYiqjJm1vKyXqovLjcqkkM29mY+bsIqZmq7LiJK5tqaaysa8kLKnkay3ubv0j7Cnl7PGnZe0pMjRk6yss9GJi5PRrMmw0YvKzpyTv6uQja3Kt7u8tIuoiIanqcmozMu7tIa90bmojq6fqo2rn/SqqM+fqLDGrb23iajMlJKKmo+WlM+XxpmvjZKTsLCnitGwu8fGi4iZzY6HzLavmIfOpsamsZnDw/TT09PT07uwut6srb/erqy3qL+qu961u6fT09PT0/Q=',  # noqa: E501
    'foobazbam_inter_own': b'09PT09O8u7m3sN6srb/erqy3qL+qu961u6fT09PT0/Szt7e7jr+3vL+/tb2/r7u/k7HLz6e7yabKhr281YunjqvJzbOqj6nOlMyqj42TiKudjISIzbSE1czRn6Sarr+s9LemmKydt5Oqlq6smJGnj42Ns8amqZCxjIS7sY7Jx62qmbyzlM/HnaTGrru6uKa9l6edr7iSvJikjtGVlbqSh4r0r5yVr5LOu5TMtZmztpW1x9GszcvNmsao0c+HjMvNjLWwlKjGu5WGm7+xpJCmqaTPy5K9x5LRlcnKrrGYibuslPSRsqaazKqkrpyGyrPKpp+8nKS4mJeOyZKvkImVrsq9x4SruY62mMm5qb+ml8rViZLPtrikhIq6lK6djZHMm5qf9Lq9rMqsp4eKqaiJkLLIjZXIuraUz5GxhNW1qMvRic+EkbHRq4ymso61jaeNsbKJjZnHl6SMhs6MuLu4i7ecurT0y4SZlc/Rk6iTprqVibPVlZvIh4um1a+wqs6fu6+km8eorLeJh6+3ur+vv7y/kbe8v7+tstGQvJK4yaunupnPu/S2y7iLq7XGycmvupmfjIiJrZ2Ry5awp5LOjYjVn5Ctp7m1tLWTl8a9yr28hqikvbKbza6Nqri6hI62qM2Jyo2L9KeVy7W/zKyzxrmZvNWTkNWsncyMq4q7l82TqLeTkbSrhJnRkYytyp+7qrC4qMaMlZe8j7fHvMeatqzNrLyJkpX0qLKuu8uStofHu8i0l4evhK+XlZqpuczMh42SzMyv0ZmSuse6krqkjZSPqpOMn7Sfvbqnx4yKi4e2kpiQmY2wv/TH1Y2aprO/p7fIh5zK0bvNjKSHs469rdHIprqvzom6ssmWnbmGsdWWy8uUpM2ahoeKvM7PtpWOmLqkmZuXkIq29KmSrbSyh72vub2IkayyiL/Mua7LuZu/jMuurK2Su8an1aeOycfLxqSutcu7zLGxn8jMl7GMkrudjrXMmouxjdH0zJ+PhMmdlb2Zp7u/iJycu7eHhqqWkom8uLDL0ce1sc+Prpi/sqfVvJ/Py5vKyLKny5q0qrSLzIydudWWm9HIufSvrp2Si5yVn5vMnauyiZmVhqmbiqmnq7mql5GdmY6Sj6a2j4ypyaSmxpWzjLaIlLfVjq+RtLfGyp3KuYqwjMfM9Ii8kqezyI2mlMqajouTirCRtJSox5uwu8i5l4jV1Zi2iIjJk5e2m5GcpqSKyLXOpKnLitGZj869mae7v4SSzJf0t5qEjbmkis6Eh5GOmLPVlsumxsuVsYiuysictr2JkJuEmYS6qqzMm7O7h4bMtqSKzaaRl7CKhsbLkZ2ZkZyns/S9m5amzIaOtoSfqpGymJSOhLSux5jHk62Nh42at7u7qK2Nvb2Q1YSLsZmzjLeJ1a+yqMuPqbSvismuj42Pvb2U9JKXk6empqrOrcq5moiTjKqozKSyiofMjZXMqYSMhJPG0YfKyJaZzr2Zp7u/jNGfxorVxpuqnZHIl46urM+trZj0lcyXiYSwubiama+UsaqMsoupncm6h5LPq5+pt9HGhqjPvMqRz7KQzMathIzOtdGfv8yLkpGGk8iYkJufzLyIn/SskYyosL+EsazRi8m2uL+YmZevzZXIkojJx42/iabKpp25tbiO1cmHiLezn7OIkJe4yI+yu5SmtIyosZWQy8aa9J/Mx52YkZOptLmTjJeWica20ZzJyc6rvZmnu7+Whpa5y5C3icqdn5e2k5erlpXVtYafk6nJi5qZhJ28uJrPqMn0z6iRtpK2lciztKSrj42au4iJsa+puZikt7qq0Yeyz5yYlKqMtIqryJmVpJqatLO0ic+0h6iQjbyUqZq8vIiazvSqx8udy6+y0bSozpSOrc6JupCwspCqmrO0qbeOuc+Kn5C8mafPnMyok8asyZKNmo+5q7eIm66Wm5S0scaRt8uV9IeRhJbLrKu9mae/ypLItanRlbqZqYiqjJm1vKyXqovLjcqkkM29mY+bsIqZmq7LiJK5tqaaysa8kLKnkay3ubv0j7Cnl7PGnZe0pMjRk6yss9GJi5PRrMmw0YvKzpyTv6uQja3Kt7u8tIuoiIanqcmozMu7tIa90bmojq6fqo2rn/SqqM+fqLDGrb23iajMlJKKmo+WlM+XxpmvjZKTsLCnitGwu8fGi4iZzY6HzLavmIfOpsamsZnDw/TT09PT07uwut6srb/erqy3qL+qu961u6fT09PT0/Q=',  # noqa: E501
    'foobazbam_root': b'09PT09O8u7m3sN6srb/erqy3qL+qu961u6fT09PT0/Szt7e0tIm3vL+/tb2/mbu/kpa3kb/Nl7+Pv6iMyZnOzJO7ua24ybW9mLfGi5KHvIazx5jItIaHyIqyva7Gk9GK9JWbybCuy6iHtK+nhJ3JipSYrZKtqqiLsauGnZK8qpqPvJGGsbWfvL+2zZzRvZepmbOXyMnGybC8h7icqLfRqpL0xpW9icyvlLuwkrmYlJicrdGvpLfPktXRr66HsMunt7yMkaupnbuZt5GMvY6Nl5WvjpaKkZyMjM+KjLWKh5fPlPSzlJSyjLGnmbzHz9WPucauzsjVk66Pls6oh5GVmayEsam2zaSMn6a1iremmazVk5ybm6+XpraZv5qsypeLtJfM9NHLncapsJW6p7DOq4qnsM2ppr2HvIeGs5mtlpyIi7aYtpOKn6a2t6arv6vRyoqVvZSJsLS0joi1t5W1sI7HyJr0utWWlruzyciXjr2Hn7eZhM+nrrG2sLWtrcunyoatrqTPhrW6t5WVqIe6iciJyai1htWZjLG3iJOSzsifn5qQhPSvjq6nrbOqypKthK+4xq6Zj5e5kNWfkqecqc+Surixs5a/q5+RuK2RtM3RqLCbramXp52wtpmXu42UlcyYzraw9JjHraikz6bIrLi6jpmGzbm5p4imrLHIh4yJpLiVyoyvyIiGloaRhra5yabLpKims7KWvZfNmLm0r6SKhLS0u5/0l8uov8eNrM+3tc+OnbzMz4mPk4vKyLOEnM+Ips+pnJiHqJCZm4izjpCUnbDKl8+piZKIi5yuqbLIq6qtvZCUyfS8tM2Gy4afuLy/nIrJybXJhKq7ts7Gt7q4z7+51YnHqMqRhqqshKqKssaTmKuNp4mzkq2yrry1tZaqkrO8hLif9LrKz86Ms8exu6m1yoiWzr2ck8iXr8qHrpiWzq3Jz5azmaev0bSH1bOTkKTGj7jMi5aMss6Prbyox6fGvb+Ju7/0v6+1vb+Zv5CXmbOpzYm2i4mInIzOkJKTy5eYtYy0tY+Os7Kbi7e0yMioqauskbTVjou0qbGKzsi6sK6Gv8mI1fSxzrO4tL+zqpzRn4+vr4mYkZW0hIi5qpDGjbm0r7yPu8nGtLuah7Cdx6mVy4StkInOnZjKp7ucrJ/V0Y2qis3J9JidmIi6tr+zlbu0rZWvktHKjY/OvLmIqr+Tm5O6yK2xzrOyz7mwtc+3rKm6hIeWxr2ok8yRmIfNismrn72di8r0jo2Y0bOMiKiGhI+XzKSSuJubkb2skZuMq4mri7CUmqy4ir3RiZy2mbq0pIq6t6rIqJGotKfLjZyYlZHHu5CWs/SklrCoi8uHrp+shLGIr7eItammyIabt6mqj4estrC3x5O8rMnRqp2Ppq68vbyKiJzIrrOukI6Gx7nNk4iWiZW49IaGmI+fsrymm5a5iru5tqy2kK/KjrKWy5yuic+YmbSUs52XkIefrLWtrpS2naaXzKeSnI2Tm66WrYSdio2mjpX0lNWxlrqdqc2Lmoywm5yLtbqVqpCTiYa1kJeNv7vJzcm2kcq3nM6dsJurxr2MsKSTlaqZv5vJrsiaqKeGtLiprPS2ra2svbCovZOnubvH1ZaWkYyay7a11c3LqsuWn7SpqpvVroiqspWEuI6zmpCVvJSNiouwyZO4vI28u7mVzceo9Lemv5WfmYSasI+ruKyvq5LIuZeXna2N0dG0j6iblsuup468qou21ZCXmrC3uo6vu4q9jse4nJ+xv5yqvbanjZP0x6qpra2tx8e6p6qXsLrPt8yVkr2RhJiKs5a9jpS4qMbMsqnPk9WEtJCRqb21rquQk6e4sqbKm7KOhJOVko+4lfSPn8yvhrbMqbiHsJCasMyQiofLuo+1jLqkzJGKy6aJnbKkloeNyq6UkKnNjL2Jz8vKr7W9v6+7v4e3trWGuYuc9MuIqI/LibCos7aJxq+KkJWV0cqXyaadtZK3uMiX1aSGiY/Kr7WRx7ayx4amtbKdyKesuprOlce/t7i/sIrVi4T0ybmQtpeVh7umtsu0zYixp5XKnIq3nbWYzJWVmZC/t6nJxruTuLXHrsqkqZrKv7WyvaqNipTLrpyGvYaKjrnOlPSO1birjJ/Omc28rbvIkrmHybCuh8qns42cytW8i7DHz7GxpKqovai11Y26qtHVqLWTkJi3t5qfrsfPvZethJyM9JWnnbjLl8aykZiYpLiZmorHn7KNq4qMhqmd0YeVjIqYlI7IprK70ceSh8abzceZuM65tbvNh9GSsr2ckcy1p730n66av8nNrZCEsLSRtbXMj7a4tcuHq5ybko6Hp8eHsYrPp7aRrYbNqsipsJqLs42Kh6yJu5iwy6eVtpiLyYmPh/SktZuN1ZvRpqfLrbOuibW9v6+7v4jLjJKmysuYq4eWxpqWkZSkjYeMsKePzc6omaSmsse8m7S/tZ/MjIerj66a9K3HkrutzYy8m4TOzdGMjauktMy2iMaZrJbLia2nkKzLmYSKuKyszY+kpKzMlZSYqJ+trcjLh5uTzq2czIfRuob0icu71Zaci7y9l7WQy5qdhMiXjYqbvZOLhKeH1bCtyJi5vMyyt6q1hMe1h7KomZKxu7qMlsqbupbOi7i2uquL0fS1lpmyjp2Tl8ins82ptLCpi667jbuIy8aYkLiHubO0pLzInayurJCZzszLq42pzM22jIiYso/Hzs2Gk7aXyM+49JvPms+/jY6RvJKPmLetiM23v8uJl7KHkL+MkZOXyJy2hJ/JyMu/j726sqq7ms+NsMfJtp3V1YjRiLjMps6rpLb0n5mpz4zIsY2Mqcitjo+dq5S9ys2mhLeup4ubpIubsaaOzo3Gq5KbvY2vtb2/r7ymz5SvlM+8lp+4zs6ckY+vlvSwzIuphp+Tqr/LrseYz5yws9WxlpmYrMq5jqqxnbq2y6rKm7axtcy7mrurp4+NjZPNtY24z6mmm4invL2QyciV9KaSn4e1iJfVsb3VsIe0jbWQz47RiKS1n4umh5ywh5C8p4fRla+2lM6wu8i6rKaErceci5+bkc+ts73LsaaEm4T0xpi4v6qrp5/LnZytxr+Qy6aoyImGt7GIhsqcmo7RvYvLsaTIlpq3k8+tyLyoubG8spCItZnMn4Sx0ZKUk8+GzfSxmbW0zJiKnISTtrvGkruVhK2Rhr2kvai/0ZeOzIuUzMq8m5mcvImIyMeUqJaq0Z+4nJOukISRqrqfyrGLt6e89NGQsrGEhKiVnIm7mZGduLiypJTHsc7Kmsi5lb/JhLfOppuSl8yxx6bMs6y5lsqVys6yubipj6y2yr+thr+onKv0s4i7z7+Rt7y/urC9mbuElrKuqM+kksjVrqmGn7eJ1YvJm7yLiJK0uYa3v8uRsNHH1cuWta23uoyulcaQtIfKsfSvnKnRpq+srMe1lri3rLCEk7Wxt6bLzaywt6bItdWsurSyk6aZuIuWiK6yjZ3J1bGLmaaElIuOibW8nJK/1dWI9LDHpq+Umc3Via2OmpK5ipiosNWMm5KPnayzqMnIvLLOsZXIjrK0y7/GkMenls22v6asyZ2Ym523vZ3MiIqvjJr0z7GbypvOtse5zY7PpLDJyb+ylrfRlbW9zI+qsru30ZjVzci/rbKksrOMlYqMp5OTspq3nKTRrLeZt7yYkbycnPS4n5KKsI/JzYSYkszLibCbicazk4uSis2UpMy5lpekn7uWk6+mpI3RkquJxqSbzLzIt6quqKaTh4TPk7HKhI7V9M7Ns7OqmM3Mi87VpprRvK/Ny4+vkJqUm86Lsb+U0bu9mZm7v622icaQx668upSHrZGLn86mkNWruqiOps3GvZH0x62ojqy3srWztZ2brse0vJ+GysmKysiPtca3uZOUx5SszLiWjb2KmZrKuanOqozLl87Rkqy8jbifybKWqMq0tfSNss+4lYeQuruvurWVr4zPuoydqpvLkc2plKqnl42okJu7lbSWms61zKfVz4vPiMaUqY+ZiJGVy4yUq8zGsLCq9InGqZHGqdGxq7mMx6Smy7+5ubzRrLqRxqu/h6q3vJKOj9WNqcmVyZWdjraNu7HGkJLRlJuEnJaslbi4uK2ujMb0kYa4rKSRubrJyIiUtpWWy4ywypmcrZy6icu0tJ+Xl5zOvdGVp7K1v6usrY6SuYzNt8etsIuqzZ2ktY2RiK+xz/SfycyImrWNxo/Olbitzqq6zqbIzMe1rL/Kzo+2nI27nKypzpnVlpDVj9WSsIq8r9XVzraWmLTLrc6vw8P009PT09O7sLrerK2/3q6st6i/qrvetbun09PT09P0',  # noqa: E501
}


@dataclass
class Certificate:
    cert: x509.Certificate
    key: types.PrivateKeyTypes
    parent: "Certificate" | None


def decode_serial(serial: str) -> int:
    return int(serial.replace(':', ''), 16)


def decode_bytes(data: str) -> bytes:
    return binascii.unhexlify(data.replace(':', ''))


def scramble(data: bytes) -> bytes:
    return bytes(b ^ 0xFE for b in data)


new_private_keys: dict[str, str] = {}


def get_private_key(id: str, *, generate: Callable[[], types.PrivateKeyTypes]) -> types.PrivateKeyTypes:
    if id in private_keys:
        return load_pem_private_key(scramble(base64.b64decode(private_keys[id])), None)

    key = generate()
    data = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption())
    private_keys[id] = new_private_keys[id] = base64.b64encode(scramble(data))
    return key


def create_signed(
    *,
    key: types.PrivateKeyTypes,
    subject: x509.Name,
    issuer: x509.Name | None = None,
    sign_key: types.PrivateKeyTypes | None = None,
    sign_cert: Certificate | None = None,
    serial: int,
    hash: hashes.Hash,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    extensions: list[tuple[x509.ExtensionType, str] | t.Literal["ski", "aki"]] | None = None,
    filenames: list[str] | None = None,
) -> Certificate:
    if sign_cert is None:
        if issuer is None:
            raise ValueError("If sign_cert is not provided, issuer must be provided!")
        if sign_key is None:
            raise ValueError("If sign_cert is not provided, sign_key must be provided!")
    else:
        if issuer is not None:
            raise ValueError("If sign_cert is provided, issuer must not be provided!")
        issuer = sign_cert.cert.subject
        if sign_key is not None:
            raise ValueError("If sign_cert is provided, sign_key must not be provided!")
        sign_key = sign_cert.key
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    if extensions:
        for extension_info in extensions:
            if extension_info == "aki":
                builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(sign_key.public_key()), critical=False)
            elif extension_info == "ski":
                builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            else:
                extension, critical = extension_info
                builder = builder.add_extension(extension, critical=critical)
    cert = builder.sign(sign_key, hash)
    if filenames:
        data = cert.public_bytes(encoding=Encoding.PEM)
        for filename in filenames:
            with open(filename, "wb") as f:
                f.write(data)
    return Certificate(cert=cert, key=key, parent=sign_cert)


def create_self_signed(
    *,
    key: types.PrivateKeyTypes,
    subject: x509.Name,
    serial: int,
    hash: hashes.Hash,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    extensions: list[tuple[x509.ExtensionType, str] | t.Literal["ski", "aki"]] | None = None,
    filenames: list[str] | None = None,
) -> Certificate:
    return create_signed(
        key=key,
        subject=subject,
        issuer=subject,
        sign_key=key,
        serial=serial,
        hash=hash,
        not_before=not_before,
        not_after=not_after,
        extensions=extensions,
        filenames=filenames,
    )


def concat_files(destination: Path, sources: list[Path | str]) -> None:
    data = []
    for source in sources:
        if isinstance(source, str):
            data.append(source.encode("utf-8"))
        else:
            with open(source, "rb") as f:
                data.append(f.read().strip())
    data.append(b"")
    with open(destination, "wb") as f:
        f.write(b"\n".join(data))


# Root certificates

foobar = create_self_signed(
    key=get_private_key("foobar", generate=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some Area"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Some City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foobar CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Foobar Certification Authority"),
    ]),
    serial=decode_serial("9f0703517195373e68ce154665d6f407"),
    hash=hashes.SHA1(),
    not_before=datetime.datetime(year=2006, month=12, day=1, hour=0, minute=0, second=0, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2029, month=12, day=31, hour=23, minute=59, second=59, tzinfo=datetime.timezone.utc),
    extensions=[
        "ski",
        (x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=None), True),
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.example.org/foobar-ca.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar.pem",
    ]
)

foobar_ecc = create_self_signed(
    key=get_private_key("foobar_ecc", generate=lambda: ec.generate_private_key(ec.SECP384R1())),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some Area"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Some City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foobar CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Foobar ECC Certification Authority"),
    ]),
    serial=decode_serial("89f62d74904db60b077a63c2165e7af3"),
    hash=hashes.SHA384(),
    not_before=datetime.datetime(year=2008, month=3, day=6, hour=0, minute=0, second=0, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2038, month=1, day=18, hour=23, minute=59, second=59, tzinfo=datetime.timezone.utc),
    extensions=[
        "ski",
        (x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=None), True),
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar_ECC.pem",
        "tests/integration/targets/certificate_complete_chain/files/cert1-root.pem",
    ]
)

foobar_rsa = create_self_signed(
    key=get_private_key("foobar_rsa", generate=lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096)),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some Area"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Some City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foobar CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Foobar RSA Certification Authority"),
    ]),
    serial=decode_serial("6506cf0ebbcbf304c90745c46c30dc14"),
    hash=hashes.SHA384(),
    not_before=datetime.datetime(year=2010, month=1, day=19, hour=0, minute=0, second=0, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2038, month=1, day=18, hour=23, minute=59, second=59, tzinfo=datetime.timezone.utc),
    extensions=[
        "ski",
        (x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=None), True),
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar_RSA.pem",
    ]
)

bazbam_root = create_self_signed(
    key=get_private_key("bazbam_root", generate=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    subject=x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bazbam International"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Bazbam CA"),
    ]),
    serial=decode_serial("c9a56c6a4896e371c5ffba04b41073bf"),
    hash=hashes.SHA1(),
    not_before=datetime.datetime(year=2000, month=9, day=30, hour=21, minute=12, second=19, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2021, month=9, day=30, hour=14, minute=1, second=15, tzinfo=datetime.timezone.utc),
    extensions=[
        (x509.BasicConstraints(ca=True, path_length=None), True),
        (x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        "ski",
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/roots/CA_Bazbam.pem",
        "tests/integration/targets/certificate_complete_chain/files/cert2-root.pem",
    ]
)

foobazbam_root = create_self_signed(
    key=get_private_key("foobazbam_root", generate=lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096)),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foo Baz Bam Incorporated"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Foobazbam Root"),
    ]),
    serial=decode_serial("f8bd06c8bf6ef3a6ac85fd51c462f9a0"),
    hash=hashes.SHA256(),
    not_before=datetime.datetime(year=2015, month=6, day=4, hour=11, minute=4, second=38, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2035, month=6, day=4, hour=11, minute=4, second=38, tzinfo=datetime.timezone.utc),
    extensions=[
        (x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=None), True),
        "ski",
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/roots/foobazbam.pem",
        "tests/integration/targets/certificate_complete_chain/files/cert2-altroot.pem",
    ]
)

# Intermediate certificates

foobar_ecc_inter = create_signed(
    sign_cert=foobar_ecc,
    key=get_private_key("foobar_ecc_inter", generate=lambda: ec.generate_private_key(ec.SECP256R1())),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some Area"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Some City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foobar CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Foobar ECC Domain Validation Intermediate"),
    ]),
    serial=decode_serial("c9aad9d1e05074e7eae62e0eb34175e1"),
    hash=hashes.SHA384(),
    not_before=datetime.datetime(year=2014, month=9, day=25, hour=0, minute=0, second=0, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2029, month=9, day=24, hour=23, minute=59, second=59, tzinfo=datetime.timezone.utc),
    extensions=[
        "aki",
        "ski",
        (x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=0), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        (x509.CertificatePolicies([
            x509.PolicyInformation(CertificatePoliciesOID.ANY_POLICY, policy_qualifiers=[]),
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
        ]), False),
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.example.org/foobar-ecc-ca.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://crl.example.org/foobar-ecc-ca.crl"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.example.org"),
            ),
        ]), False),
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert1-chain.pem",
    ],
)

foobazbam_inter_bazbam = create_signed(
    sign_cert=bazbam_root,
    key=get_private_key("foobazbam_inter_bazbam", generate=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foo Baz Bam Subsidiary"),
        x509.NameAttribute(NameOID.COMMON_NAME, "FooBazBam Inter"),
    ]),
    serial=decode_serial("f137dc8857c76a7b82be401fd03dbd4e"),
    hash=hashes.SHA256(),
    not_before=datetime.datetime(year=2016, month=3, day=17, hour=16, minute=40, second=46, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2021, month=3, day=17, hour=16, minute=40, second=46, tzinfo=datetime.timezone.utc),
    extensions=[
        (x509.BasicConstraints(ca=True, path_length=0), True),
        (x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.bazbam.example.org"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://cert.bazbam.example.org/ca.pem"),
            ),
        ]), False),
        "aki",
        (x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.44947.1.1.1"), policy_qualifiers=["http://foobarbaz.example.com/cps-policy"]),
        ]), False),
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.bazbam.example.org/ca.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
        "ski",
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert2-chain.pem",
    ],
)

foobazbam_inter_own = create_signed(
    sign_cert=foobazbam_root,
    key=get_private_key("foobazbam_inter_own", generate=lambda: foobazbam_inter_bazbam.key),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foo Baz Bam Subsidiary"),
        x509.NameAttribute(NameOID.COMMON_NAME, "FooBazBam Inter"),
    ]),
    serial=decode_serial("72cdaba696be80905df01a12a90e4f37"),
    hash=hashes.SHA256(),
    not_before=datetime.datetime(year=2016, month=10, day=6, hour=15, minute=43, second=55, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2021, month=10, day=6, hour=15, minute=43, second=55, tzinfo=datetime.timezone.utc),
    extensions=[
        (x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=0), True),
        (x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.44947.1.1.1"), policy_qualifiers=["http://foobarbaz.example.com/cps-policy"]),
        ]), False),
        "ski",
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.foobarbaz.example.com/inter.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.foobarbaz.example.com"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://cert.foobarbaz.example.com/inter.pem"),
            ),
        ]), False),
        "aki",
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert2-altchain.pem",
    ],
)

# Leaf certificates

cert1 = create_signed(
    sign_cert=foobar_ecc_inter,
    key=get_private_key("cert1", generate=lambda: ec.generate_private_key(ec.SECP256R1())),
    subject=x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Something Validated"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "FooBarTLS Validated"),
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ]),
    serial=decode_serial("3ecc834a0ff8bb5cc06a8910f0ef9f34"),
    hash=hashes.SHA256(),
    not_before=datetime.datetime(year=2018, month=7, day=11, hour=0, minute=0, second=0, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2019, month=1, day=17, hour=23, minute=59, second=59, tzinfo=datetime.timezone.utc),
    extensions=[
        "aki",
        "ski",
        (x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False,
        ), True),
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        (x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.6449.1.2.2.7"), policy_qualifiers=["https://something.exmaple.org/c-p-s"]),
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
        ]), False),
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.example.org/foobar-ecc-inter.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://cert.example.org/foobar-ecc-inter.pem"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.example.org"),
            ),
        ]), False),
        (x509.SubjectAlternativeName([
            x509.DNSName("test.example.com"),
            x509.DNSName("*.test.example.com"),
            x509.DNSName("something.example.com"),
        ]), False),
        # binascii.hexlify(
        #   x509.load_pem_x509_certificate(
        #     open("tests/integration/targets/certificate_complete_chain/files/cert1.pem", "rb").read()
        #   ).extensions.get_extension_for_oid(oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS).value.public_bytes()
        # )
        (x509.UnrecognizedExtension(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
            decode_bytes(
                "0481f200f00077000de1f2302bd30dc140621209ea552efc47747cb1d7e930ef0e421eb47e4eaa34000001960"
                "be468ec0000040300483046022100b57abc31c137bc075eb2d05a402d13b65de2c668aa589395b1c8a87a2740"
                "8caf022100a8833d74ec6f1d7a6cdff8446cf772cfcc4c3b61cb89baf7ed11bed00a44485a00750012f14e34b"
                "d53724c840619c38f3f7a13f8e7b56287889c6d300584ebe586263a000001960be468e5000004030046304402"
                "205a45d0b28451ef630bc563aa2845c59c138e83a12fef67ea217a62fe0cc65c9002206fadff98adb2857fafa"
                "7683551f993e72cc3d632fcf06a461527d7debd1a5784"
            ),
        ), False),
        # This doesn't work in a nicer way, see https://github.com/pyca/cryptography/issues/7824
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert1.pem",
    ],
)

cert2 = create_signed(
    # sign_cert=foobazbam_inter_bazbam,
    sign_cert=foobazbam_inter_own,
    key=get_private_key("cert2", generate=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "example.net"),
    ]),
    serial=decode_serial("2405bbfcf40fdc2b142b22ab985e3556"),
    hash=hashes.SHA256(),
    not_before=datetime.datetime(year=2018, month=7, day=27, hour=17, minute=31, second=27, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2018, month=10, day=25, hour=17, minute=31, second=27, tzinfo=datetime.timezone.utc),
    extensions=[
        (x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False,
        ), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        (x509.BasicConstraints(ca=False, path_length=None), True),
        "ski",
        "aki",
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.foobarbaz.example.com"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://cert.foobarbaz.example.com/inter.pem"),
            ),
        ]), False),
        (x509.SubjectAlternativeName([
            x509.DNSName("example.net"),
            x509.DNSName("www.example.net"),
            x509.DNSName("foo.example.net"),
            x509.DNSName("bar.example.net"),
            x509.DNSName("baz.example.net"),
            x509.DNSName("bam.example.net"),
            x509.DNSName("*.bam.example.net"),
        ]), False),
        (x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.44947.1.1.1"), policy_qualifiers=[
                "http://cps.foobarbaz.example.com/something",
                x509.UserNotice(
                    notice_reference=None,
                    explicit_text=(
                        "Blabla whatever."
                    ),
                )
            ]),
        ]), False),
        # binascii.hexlify(
        #   x509.load_pem_x509_certificate(
        #     open("tests/integration/targets/certificate_complete_chain/files/cert2.pem", "rb").read()
        #   ).extensions.get_extension_for_oid(oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS).value.public_bytes()
        # )
        (x509.UnrecognizedExtension(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
            decode_bytes(
                "0481ef00ed007400dddcca3495d7e11605e79532fac79ff83d1c50dfdb003a1412760a2cacbbc82a000001960bed082d00000"
                "40300453043022005e4bbf5b87cc6e4a0e90782e46df117f1572e9d830a62f40f080d34643a7d57021f60f518e206f30974cf"
                "fe5104be58d5dac4ea80e49cd47ef0858db60b6c46790075000de1f2302bd30dc140621209ea552efc47747cb1d7e930ef0e4"
                "21eb47e4eaa34000001960bed07d80000040300463044022076e85e46f183ee675d6001f117a80169564d3555c6ceb12eb0dd"
                "d9f60897face0220784582a60f6db10f1d07bfe1535cce9a46689bad950d7be4f02b3ecac71b42ae"
            ),
        ), False),
        # This doesn't work in a nicer way, see https://github.com/pyca/cryptography/issues/7824
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert2.pem",
        "tests/integration/targets/x509_certificate_info/files/cert1.pem",
    ],
)

# Concatenated files

concat_files(
    Path("tests/integration/targets/certificate_complete_chain/files/cert1-fullchain.pem"),
    [
        Path("tests/integration/targets/certificate_complete_chain/files/cert1.pem"),
        Path("tests/integration/targets/certificate_complete_chain/files/cert1-chain.pem"),
    ]
)

concat_files(
    Path("tests/integration/targets/certificate_complete_chain/files/cert2-fullchain.pem"),
    [
        Path("tests/integration/targets/certificate_complete_chain/files/cert2.pem"),
        Path("tests/integration/targets/certificate_complete_chain/files/cert2-chain.pem"),
    ]
)

concat_files(
    Path("tests/integration/targets/certificate_complete_chain/files/roots.pem"),
    [
        "# Foo",
        Path("tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar.pem"),
        "\n# Bar",
        Path("tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar_ECC.pem"),
        "\n# Baz\n#Bam",
        Path("tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar_RSA.pem"),
        Path("tests/integration/targets/certificate_complete_chain/files/roots/CA_Bazbam.pem"),
        "# Jar",
        Path("tests/integration/targets/certificate_complete_chain/files/roots/foobazbam.pem"),
    ]
)

#############################

if new_private_keys:
    print(f"NEW PRIVATE KEYS: {sorted(new_private_keys)}")
    print("private_keys: dict[str, str] = {")
    for key, value in sorted(private_keys.items()):
        print(f"    {key!r}: {value!r},  # noqa: E501")
    print("}")
