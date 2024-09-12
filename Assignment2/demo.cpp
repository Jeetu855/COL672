#include<bits/stdc++.h>
#include<algorithm>
using namespace std;
void removeNewLines(string &text)
{
           text.erase(remove(text.begin(),text.end(),'\n'),text.end());

};
int main()
{
//    //string str="apple,banana,orange,grape,strawberry,blueberry,raspberry,blackberry,kiwi,pear,plum,peach,cherry,nectarine,apricot,fig,grapefruit,lemon,lime,melon,watermelon,apricot,kiwi,passionfruit,pomegranate,dragonfruit,guava,kiwifruit,olive,mandarin,tangerine,starfruit,plantain,pluot,plumcot,grapefruit,gooseberry,cranberry,lingonberry,coconut,mango,papaya,dates,loquat, quince,elderberry,orange,blueberry,redcurrant,jackfruit,lychee,papaya,dragonfruit,pomegranate,rhubarb,carambola,cherimoya,langsat,carrot,celery,cucumber,corn,spinach,broccoli,cabbage,cauliflower,greenbean,asparagus,zucchini,eggplant,artichoke,kale,mushroom,pea,beet,turnip,rutabaga,sweetpotato,radish,parsnip,brusselsprout,leek,onion,shallot,garlic,ginger,rosemary,thyme,basil,chive,cilantro,dill,mint,sage,oregano,thyme,arugula,watercress,radicchio,fennel,cress,watermelon radish,daikon,hibiscus,monstera,jerusalem artichoke,mizuna,daikon radish,shiitake,portobello,cremini,chanterelle,morel,hen-of-the-woods,shimeji,maitake,porcini,enoki,hen of the woods, button mushroom,beefsteak tomato,roma tomato,heirloom tomato,green tomato,yellow tomato,";
//     string str="apple,1233545 rohit patidar,1233545,1233545,red ,carpet,carrot,apple,carrot,apple,carrot,abcd,abcd,abcd,juice, EOF";
//     map<string,int> freq;
//     for (int i=0;i<str.size();i++)
//          {
//               string s1="";
//               while(i<str.size() && str[i]!=',' )
//                     {
//                         s1+=str[i];
//                         i=i+1;
//                     }
//                if(s1==" EOF")
//                   continue;     
//                freq[s1]=freq[s1]+1;     
//          };
//     map<string,int> ::iterator it =freq.begin();
//     while(it!=freq.end())
//       {
//         cout<<it->first<<"-"<<it->second<<endl;
//         ++it;
//       }  ;
    string text = "Hello\nWorld\nThis\nis\nC++\n";
    cout<<text;
    removeNewLines(text);
    cout<<"\nAfter remove"<<text;
       
};